//! Native fixture process used by process ownership and renderer regressions.
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
fn docker(args: &[String]) {
    let locator = args.get(2).unwrap().replacen("unix:", "file:", 1);
    let state = url::Url::parse(&locator).unwrap().to_file_path().unwrap();
    let alive = state.join("alive");
    let id = "a".repeat(64);
    if args.iter().any(|s| s == "info") {
        print!("{}", fs::read_to_string(state.join("info.json")).unwrap());
    } else if args.iter().any(|s| s == "ps") {
        if alive.exists() {
            println!("{id}");
        }
    } else if args.iter().any(|s| s == "inspect") {
        let run = fs::read_to_string(state.join("run")).unwrap();
        println!(
            "{}",
            serde_json::json!([{"Id":id,"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{"org.revayat.tex.run":run}}}])
        );
    } else if args.iter().any(|s| s == "rm") {
        fs::remove_file(alive).unwrap();
    } else {
        std::process::exit(2);
    }
}
fn browser_protocol(args: &[String]) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use lopdf::{Document, Object, dictionary};
    use serde_json::json;
    let profile = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--user-data-dir="))
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    fs::write(
        Path::new(profile).join("DevToolsActivePort"),
        format!("{port}\n/devtools/browser/fixture\n"),
    )
    .unwrap();
    let mut socket = tungstenite::accept(listener.accept().unwrap().0).unwrap();
    loop {
        let message = socket.read().unwrap();
        let tungstenite::Message::Text(text) = message else {
            continue;
        };
        let request: serde_json::Value = serde_json::from_str(&text).unwrap();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "Browser.getVersion" => json!({"product":"Fixture/1","protocolVersion":"1.3"}),
            "Target.getTargets" => json!({"targetInfos":[{"type":"page","targetId":"fixture"}]}),
            "Target.attachToTarget" => json!({"sessionId":"fixture"}),
            "Page.printToPDF" => {
                let mut pdf = Document::with_version("1.7");
                let pages = pdf.new_object_id();
                let content = pdf.add_object(lopdf::Stream::new(dictionary! {}, Vec::new()));
                let page = pdf.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![0.into(),0.into(),200.into(),300.into()],"Resources"=>dictionary!{},"Contents"=>content});
                pdf.objects.insert(pages, Object::Dictionary(dictionary!{"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}));
                let catalog = pdf.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
                pdf.trailer.set("Root", catalog);
                let mut bytes = Vec::new();
                pdf.save_to(&mut bytes).unwrap();
                json!({"data":STANDARD.encode(bytes)})
            }
            _ => json!({}),
        };
        socket
            .send(tungstenite::Message::Text(
                json!({"id":request["id"],"result":result})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        if method == "Page.navigate" {
            socket
                .send(tungstenite::Message::Text(
                    json!({"method":"Page.loadEventFired"}).to_string().into(),
                ))
                .unwrap();
        }
        if method == "Page.printToPDF" {
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
    }
}
fn main() {
    let args = env::args().collect::<Vec<_>>();
    if Path::new(&args[0])
        .file_stem()
        .is_some_and(|n| n == "docker")
    {
        docker(&args);
        return;
    }
    if Path::new(&args[0])
        .file_stem()
        .is_some_and(|n| n == "pdftoppm")
    {
        let state = env::var_os("REVAYAT_TEST_RASTER_STATE").unwrap();
        if Path::new(&state).exists() {
            std::process::exit(42);
        }
        fs::write(state, b"first raster").unwrap();
        let status = Command::new(env::var_os("REVAYAT_REAL_PDFTOPPM").unwrap())
            .args(&args[1..])
            .status()
            .unwrap();
        std::process::exit(status.code().unwrap_or(2));
    }
    match args.get(1).map(String::as_str) {
        Some("package-relocated-index") => {
            let (source, repository, output) = (
                Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4]),
            );
            let mut reached = false;
            let result = revayat_scientific::distribution_package::package_observed(
                source, repository, output, None,
                |boundary, _| {
                    if boundary == revayat_scientific::distribution_package::PackageBoundary::Staged {
                        // SAFETY: dedicated child, no live threads; only its own environment changes.
                        unsafe { env::set_var("GIT_INDEX_FILE", output); }
                        reached = true;
                    }
                    Ok(())
                },
            );
            println!("staged={reached}");
            std::process::exit(if result.is_err() { 2 } else { 0 });
        }
        Some("runtime-environment-parent") => {
            let mut spec = revayat_scientific::runtime::CommandSpec::new(args.get(2).expect("fixture program missing"));
            spec.args = vec!["runtime-environment".into(), args.get(3).expect("fixture PATH missing").into()];
            spec.env.insert("PATH".into(), args[3].clone().into());
            spec.env.insert("REVAYAT_TEST_ENV".into(), "explicit fixture override".into());
            spec.timeout = Duration::from_secs(5);
            match revayat_scientific::runtime::run(&spec) {
                Ok(output) => {
                    io::stdout().write_all(&output.stdout).unwrap();
                    std::process::exit(output.code);
                }
                Err(_) => std::process::exit(2),
            }
        }
        Some("runtime-environment") => {
            let expected_path = args.get(2).expect("fixture PATH expectation missing");
            println!("path_matches={}", env::var_os("PATH").as_deref() == Some(std::ffi::OsStr::new(expected_path)));
            println!("override_matches={}", env::var("REVAYAT_TEST_ENV").as_deref() == Ok("explicit fixture override"));
            println!("inherited_matches={}", env::var("REVAYAT_TEST_INHERITED").as_deref() == Ok("controlled inherited fixture"));
        }
        Some("echo-input") => {
            io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap();
        }
        Some("flood") => {
            for _ in 0..128 {
                io::stdout().write_all(&[b'x'; 8192]).unwrap();
            }
        }
        Some("silent") => loop {
            thread::sleep(Duration::from_secs(60));
        },
        Some("diagnostics") => {
            println!("{}", env::var("REVAYAT_TEST_ENV").unwrap_or_default());
            io::stdout().write_all(&[255]).unwrap();
            io::stderr().write_all(&[254]).unwrap();
            std::process::exit(7);
        }
        Some("launch-grandchild") | Some("wait-grandchild") => {
            let child = Command::new(env::current_exe().unwrap())
                .arg("silent")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            fs::write(&args[2], child.id().to_string()).unwrap();
            // This fixture deliberately transfers reaping to the surviving
            // runtime group/job owner, including when this launcher exits.
            std::mem::forget(child);
            if args[1] == "wait-grandchild" {
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
        }
        Some("run-nested") => {
            let mut spec =
                revayat_scientific::runtime::CommandSpec::new(env::current_exe().unwrap());
            spec.args = vec!["wait-grandchild".into(), args[2].clone().into()];
            spec.timeout = Duration::from_secs(60);
            let output = revayat_scientific::runtime::run(&spec);
            std::process::exit(if output.is_ok() { 0 } else { 2 });
        }
        Some("fake-browser") | Some("--headless") => {
            if let Some(destination) = env::var_os("REVAYAT_TEST_BROWSER_MARKER") {
                fs::write(
                    Path::new(&destination),
                    env::current_dir().unwrap().to_string_lossy().as_bytes(),
                )
                .unwrap();
            }
            let mode = Path::new(&args[0]).file_stem().unwrap().to_string_lossy();
            match mode.strip_prefix("browser-").unwrap_or("early") {
                "protocol" => browser_protocol(&args),
                "silent" => loop {
                    thread::sleep(Duration::from_secs(60));
                },
                "flood" => {
                    for _ in 0..128 {
                        if io::stderr().write_all(&[b'x'; 8192]).is_err() {
                            break;
                        }
                    }
                }
                "invalid" => {
                    io::stderr()
                        .write_all(b"\xff\xfePRIVATE_BROWSER_CANARY\n")
                        .unwrap();
                }
                "ready-exit" => {
                    let profile = args
                        .iter()
                        .find_map(|arg| arg.strip_prefix("--user-data-dir="))
                        .unwrap();
                    fs::write(
                        Path::new(profile).join("DevToolsActivePort"),
                        "0\n/devtools/browser/fixture\n",
                    )
                    .unwrap();
                    while !Path::new(profile).join("exit-now").exists() {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                "ready-private" => {
                    let profile = args
                        .iter()
                        .find_map(|arg| arg.strip_prefix("--user-data-dir="))
                        .expect("browser profile argument missing");
                    fs::write(
                        Path::new(profile).join("DevToolsActivePort"),
                        "0\n/devtools/browser/private-token\n",
                    )
                    .unwrap();
                    eprintln!("PRIVATE_BROWSER_CANARY secret-profile");
                    io::stderr().write_all(&[255, 254, b'\n']).unwrap();
                    loop {
                        thread::sleep(Duration::from_secs(60));
                    }
                }
                "held" => {
                    let child = Command::new(env::current_exe().unwrap())
                        .arg("silent")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .unwrap();
                    let destination = Path::new(&args[0])
                        .parent()
                        .unwrap()
                        .join("browser-child.pid");
                    fs::write(destination, child.id().to_string()).unwrap();
                    std::mem::forget(child);
                }
                "private" => eprintln!(
                    "PRIVATE_BROWSER_CANARY secret-profile https://private.invalid/devtools/browser/private-token"
                ),
                _ => eprintln!(
                    "No usable sandbox! PRIVATE_BROWSER_CANARY devtools/browser/private-token"
                ),
            }
            std::process::exit(42);
        }
        Some("register-container") => {
            let root = Path::new(&args[2]);
            let state = root.join("docker-state");
            fs::create_dir(&state).unwrap();
            let stage = root.join(".revayat-tex-fixture");
            fs::create_dir(&stage).unwrap();
            let run = "b".repeat(32);
            fs::write(stage.join("container.cid"), "a".repeat(64)).unwrap();
            fs::write(state.join("run"), &run).unwrap();
            fs::write(state.join("alive"), b"owned").unwrap();
            let config = revayat_scientific::tex_container::RuntimeConfig {
                base: vec![
                    args[3].clone(),
                    "--host".into(),
                    url::Url::from_file_path(&state)
                        .unwrap()
                        .to_string()
                        .replacen("file:", "unix:", 1),
                ],
                kind: "docker".into(),
                image: format!("sha256:{}", "a".repeat(64)),
            };
            revayat_scientific::tex_supervisor::register(&config, &stage, &run).unwrap();
            fs::write(root.join("registered"), b"yes").unwrap();
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        _ => {
            eprintln!("unknown fixture mode");
            std::process::exit(2);
        }
    }
}
