use super::*;
use std::collections::BTreeMap;

const TEST_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OLD_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";
const TAG: &str = "v2.1.0";

struct FakeApi {
    reads: BTreeMap<String, Value>,
    mutations: Vec<(String, Value)>,
    fail_get: Option<String>,
    tag_after_upload: Option<Option<Value>>,
    publish_response: Value,
}
impl FakeApi {
    fn new() -> Self {
        Self {
            reads: BTreeMap::from([
                (
                    format!("releases/tags/{TAG}"),
                    json!({"id":123,"tag_name":TAG,"target_commitish":TEST_SHA}),
                ),
                (
                    "releases/123/assets?per_page=100&page=1".into(),
                    json!([{ "id":456,"name":"fixture.zip" }]),
                ),
            ]),
            mutations: Vec::new(),
            fail_get: None,
            tag_after_upload: None,
            publish_response: json!({"id":123,"tag_name":TAG,"draft":false}),
        }
    }
}
impl ReleaseApi for FakeApi {
    fn get(&mut self, path: &str) -> Result<Option<Value>> {
        ensure!(
            self.fail_get.as_deref() != Some(path),
            "fixture transport failure"
        );
        Ok(self.reads.get(path).cloned())
    }
    fn json(&mut self, method: Method, path: &str, body: &Value) -> Result<Value> {
        self.mutations
            .push((format!("{method} {path}"), body.clone()));
        if method == Method::PATCH && body["draft"] == false {
            return Ok(self.publish_response.clone());
        }
        Ok(json!({"id":123,"tag_name":TAG,"draft":true}))
    }
    fn delete(&mut self, path: &str) -> Result<()> {
        self.mutations.push((format!("DELETE {path}"), Value::Null));
        Ok(())
    }
    fn upload(&mut self, id: u64, name: &str, bytes: Vec<u8>) -> Result<Value> {
        self.mutations
            .push((format!("UPLOAD {id}/{name}"), json!(bytes.len())));
        if let Some(replacement) = self.tag_after_upload.take() {
            let reference = format!("git/ref/tags/{TAG}");
            if let Some(value) = replacement {
                self.reads.insert(reference, value);
            } else {
                self.reads.remove(&reference);
            }
        }
        Ok(json!({"name":name,"state":"uploaded"}))
    }
}

fn fixture() -> (
    tempfile::TempDir,
    Vec<(String, crate::identity::Fingerprint)>,
) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fixture.zip");
    fs::write(&path, b"verified fixture bytes").unwrap();
    let fingerprint = crate::identity::file_identity(&path, None).unwrap();
    (temp, vec![("fixture.zip".into(), fingerprint)])
}

#[test]
fn existing_tag_at_a_different_commit_never_mutates_the_release() {
    let (temp, uploads) = fixture();
    let mut api = FakeApi::new();
    api.reads.insert(
        format!("git/ref/tags/{TAG}"),
        json!({"ref":format!("refs/tags/{TAG}"),"object":{"type":"commit","sha":OLD_SHA}}),
    );
    let result = publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads);
    assert!(
        result.is_err(),
        "a release must use its tag's source revision"
    );
    assert!(
        api.mutations.is_empty(),
        "wrong source must fail before remote mutation"
    );
}

fn tag_reference(kind: &str, sha: &str) -> Value {
    json!({"ref":format!("refs/tags/{TAG}"),"object":{"type":kind,"sha":sha}})
}

#[test]
fn lightweight_and_nested_annotated_tags_must_resolve_to_the_built_commit() {
    for depth in [0, 1, 3, 16] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        let ids: Vec<String> = (1..=depth).map(|id| format!("{id:040x}")).collect();
        api.reads.insert(
            format!("git/ref/tags/{TAG}"),
            tag_reference(
                if depth == 0 { "commit" } else { "tag" },
                ids.first().map_or(TEST_SHA, String::as_str),
            ),
        );
        for (index, sha) in ids.iter().enumerate() {
            let next = ids.get(index + 1);
            api.reads.insert(
                format!("git/tags/{sha}"),
                json!({"sha":sha,"object":{"type":if next.is_some(){"tag"}else{"commit"},"sha":next.map_or(TEST_SHA,String::as_str)}}),
            );
        }
        publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).unwrap();
        let final_update = api.mutations.last().unwrap();
        assert_eq!(final_update.0, "PATCH releases/123");
        assert_eq!(
            final_update.1,
            json!({"tag_name":TAG,"draft":false,"target_commitish":TEST_SHA})
        );
    }
}

#[test]
fn a_missing_tag_is_created_at_the_explicit_built_commit_including_draft_reruns() {
    for existing_draft in [false, true] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        if existing_draft {
            api.reads.get_mut(&format!("releases/tags/{TAG}")).unwrap()["target_commitish"] =
                json!(OLD_SHA);
        } else {
            api.reads.remove(&format!("releases/tags/{TAG}"));
        }
        publish_verified(
            &mut api,
            temp.path(),
            TAG,
            &TEST_SHA.to_ascii_uppercase(),
            uploads,
        )
        .unwrap();
        let updates: Vec<_> = api
            .mutations
            .iter()
            .filter(|(request, _)| request.starts_with("POST ") || request.starts_with("PATCH "))
            .collect();
        assert_eq!(updates.len(), if existing_draft { 2 } else { 3 });
        assert!(
            updates
                .iter()
                .all(|(_, body)| body["target_commitish"] == TEST_SHA)
        );
        let patches = &updates[updates.len() - 2..];
        for ((request, body), draft) in patches.iter().zip([true, false]) {
            assert_eq!(request, "PATCH releases/123");
            assert_eq!(
                *body,
                json!({"tag_name":TAG,"draft":draft,"target_commitish":TEST_SHA})
            );
        }
    }
}

#[test]
fn final_update_must_confirm_the_requested_tag_and_published_state() {
    for response in [
        json!({"id":123,"tag_name":"untagged-123456","draft":false}),
        json!({"id":123,"tag_name":TAG,"draft":true}),
    ] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        api.publish_response = response.clone();
        let error = publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads)
            .expect_err("an invalid final release response must fail publication");
        assert!(
            error
                .to_string()
                .contains("GitHub did not confirm publication"),
            "response {response} produced an unexpected error: {error:#}"
        );
    }
}

#[test]
fn malformed_foreign_missing_and_cyclic_tag_objects_refuse_all_mutations() {
    let object_sha = "a".repeat(40);
    let variants = [
        tag_reference("blob", TEST_SHA),
        tag_reference("commit", "not-a-sha"),
        json!({"ref":"refs/tags/another-version","object":{"type":"commit","sha":TEST_SHA}}),
        tag_reference("tag", &object_sha),
    ];
    for reference in variants {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        api.reads.insert(format!("git/ref/tags/{TAG}"), reference);
        assert!(publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).is_err());
        assert!(api.mutations.is_empty());
    }
    for object in [
        json!({"sha":OLD_SHA,"object":{"type":"commit","sha":TEST_SHA}}),
        json!({"sha":object_sha,"object":{"type":"tag","sha":object_sha}}),
    ] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        api.reads.insert(
            format!("git/ref/tags/{TAG}"),
            tag_reference("tag", &object_sha),
        );
        api.reads.insert(format!("git/tags/{object_sha}"), object);
        assert!(publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).is_err());
        assert!(api.mutations.is_empty());
    }
    let (temp, uploads) = fixture();
    let mut api = FakeApi::new();
    api.reads.insert(
        format!("git/ref/tags/{TAG}"),
        tag_reference("tag", &format!("{:040x}", 1)),
    );
    for index in 1..=17 {
        let sha = format!("{index:040x}");
        api.reads.insert(
            format!("git/tags/{sha}"),
            json!({"sha":sha,"object":{"type":"tag","sha":format!("{:040x}",index+1)}}),
        );
    }
    assert!(publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).is_err());
    assert!(api.mutations.is_empty());
}

#[test]
fn tag_read_errors_and_mismatched_release_metadata_are_not_missing_tag_authority() {
    for failed_read in [true, false] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        if failed_read {
            api.fail_get = Some(format!("git/ref/tags/{TAG}"));
        } else {
            api.reads.get_mut(&format!("releases/tags/{TAG}")).unwrap()["tag_name"] =
                json!("other-version");
        }
        assert!(publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).is_err());
        assert!(api.mutations.is_empty());
    }
}

#[test]
fn a_tag_changed_or_deleted_during_upload_cannot_publish_the_draft() {
    for replacement in [Some(tag_reference("commit", OLD_SHA)), None] {
        let (temp, uploads) = fixture();
        let mut api = FakeApi::new();
        api.reads.insert(
            format!("git/ref/tags/{TAG}"),
            tag_reference("commit", TEST_SHA),
        );
        api.tag_after_upload = Some(replacement);
        assert!(publish_verified(&mut api, temp.path(), TAG, TEST_SHA, uploads).is_err());
        assert!(
            api.mutations
                .iter()
                .any(|(request, _)| request.starts_with("UPLOAD "))
        );
        assert!(
            api.mutations
                .iter()
                .all(|(_, body)| body.get("draft") != Some(&json!(false)))
        );
    }
}
