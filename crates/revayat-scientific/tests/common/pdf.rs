#![allow(dead_code)]
use lopdf::{
    Document, Object, ObjectId, Stream,
    content::{Content, Operation},
    dictionary,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub source: PathBuf,
    pub output: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = temp.path().join("source.pdf");
        let output = temp.path().join("output.pdf");
        Self {
            temp,
            source,
            output,
        }
    }
    pub fn save(&self, mut d: Document) {
        d.save(&self.source).unwrap();
    }
    pub fn previous(&self) {
        fs::write(&self.output, b"previous approved delivery").unwrap();
    }
    pub fn preserved(&self) {
        assert_eq!(
            fs::read(&self.output).unwrap(),
            b"previous approved delivery"
        );
    }
}
pub fn document(n: usize) -> Document {
    let mut d = Document::with_version("1.7");
    let root = d.new_object_id();
    let font=d.add_object(dictionary!{"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica","Encoding"=>"WinAnsiEncoding"});
    let resources = d.add_object(dictionary! {"Font"=>dictionary!{"F1"=>font}});
    let mut kids = Vec::new();
    for i in 0..n {
        let content = d.add_object(Stream::new(
            dictionary! {},
            Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
                    Operation::new("Td", vec![30.into(), 250.into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal(format!(
                            "Untouched source {}",
                            i + 1
                        ))],
                    ),
                    Operation::new("ET", vec![]),
                ],
            }
            .encode()
            .unwrap(),
        ));
        let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>root,"Contents"=>content,"Resources"=>resources,"MediaBox"=>vec![0.into(),0.into(),400.into(),500.into()]});
        kids.push(page.into());
    }
    d.objects.insert(
        root,
        Object::Dictionary(dictionary! {"Type"=>"Pages","Kids"=>kids,"Count"=>n as i64}),
    );
    let catalog = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>root});
    d.trailer.set("Root", catalog);
    d
}
pub fn pages(d: &Document) -> Vec<ObjectId> {
    revayat_scientific::pdf::page_ids(d).unwrap()
}
pub fn append_annot(d: &mut Document, page: ObjectId, id: ObjectId) {
    let dict = d.get_object_mut(page).unwrap().as_dict_mut().unwrap();
    if !dict.has(b"Annots") {
        dict.set("Annots", Vec::<Object>::new());
    }
    dict.get_mut(b"Annots")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(id.into());
}
pub fn appearance(d: &mut Document, on: bool) -> ObjectId {
    let bytes = if on {
        b"q 0 g 1 1 12 12 re f Q".to_vec()
    } else {
        Vec::new()
    };
    d.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Form","BBox"=>vec![0.into(),0.into(),15.into(),15.into()]},bytes))
}
pub fn checkbox(d: &mut Document, name: &str, state: &str) -> ObjectId {
    let off = appearance(d, false);
    let on = appearance(d, true);
    let mut states = lopdf::Dictionary::new();
    states.set("Off", off);
    states.set(state.as_bytes(), on);
    let page = pages(d)[0];
    let id=d.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Widget","FT"=>"Btn","T"=>Object::string_literal(name),"Rect"=>vec![20.into(),30.into(),35.into(),45.into()],"AP"=>dictionary!{"N"=>states},"AS"=>"Off","V"=>"Off","Ff"=>0});
    append_annot(d, page, id);
    register_field(d, id);
    id
}
pub fn register_field(d: &mut Document, id: ObjectId) {
    let mut form = if let Ok(o) = d.catalog().unwrap().get(b"AcroForm") {
        revayat_scientific::pdf_navigation::resolved(d, o)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone()
    } else {
        dictionary! {"Fields"=>Vec::<Object>::new()}
    };
    form.get_mut(b"Fields")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(id.into());
    d.catalog_mut().unwrap().set("AcroForm", form);
}
pub fn textfield(d: &mut Document, name: &str) -> ObjectId {
    let page = pages(d)[0];
    let ap = appearance(d, false);
    let id=d.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Widget","FT"=>"Tx","T"=>Object::string_literal(name),"V"=>Object::string_literal("old"),"Rect"=>vec![40.into(),80.into(),260.into(),105.into()],"AP"=>dictionary!{"N"=>ap},"Ff"=>0});
    append_annot(d, page, id);
    register_field(d, id);
    id
}
pub fn radio(d: &mut Document, name: &str, labels: &[&str]) -> (ObjectId, Vec<ObjectId>) {
    let parent = d.add_object(
        dictionary! {"FT"=>"Btn","T"=>Object::string_literal(name),"Ff"=>1<<15,"V"=>"Off"},
    );
    let mut kids = Vec::new();
    for label in labels {
        let off = appearance(d, false);
        let on = appearance(d, true);
        let mut states = lopdf::Dictionary::new();
        states.set("Off", off);
        states.set(label.as_bytes(), on);
        let id=d.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Widget","Parent"=>parent,"Rect"=>vec![20.into(),120.into(),35.into(),135.into()],"AP"=>dictionary!{"N"=>states},"AS"=>"Off"});
        append_annot(d, pages(d)[0], id);
        kids.push(id);
    }
    d.get_object_mut(parent)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set(
            "Kids",
            kids.iter()
                .copied()
                .map(Object::Reference)
                .collect::<Vec<_>>(),
        );
    register_field(d, parent);
    (parent, kids)
}
pub fn link(d: &mut Document, page: usize, target: usize, tail: Vec<Object>) -> ObjectId {
    let p = pages(d);
    let mut dest = vec![p[target].into()];
    dest.extend(tail);
    let id=d.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Link","Rect"=>vec![20.into(),40.into(),140.into(),65.into()],"Dest"=>dest});
    append_annot(d, p[page], id);
    id
}
pub fn outline(d: &mut Document, mode: &str, args: Vec<Object>) -> ObjectId {
    let root = d.new_object_id();
    let mut dest = vec![
        (*pages(d).last().unwrap()).into(),
        Object::Name(mode.as_bytes().to_vec()),
    ];
    dest.extend(args);
    let first=d.add_object(dictionary!{"Parent"=>root,"Title"=>Object::String(vec![0xfe,0xff,6,0x39,6,0x46,6,0x48,6,0x27,6,0x46],lopdf::StringFormat::Hexadecimal),"Dest"=>dest,"F"=>3,"C"=>vec![0.2.into(),0.4.into(),0.6.into()]});
    let second=d.add_object(dictionary!{"Parent"=>first,"Title"=>Object::string_literal("Reference"),"A"=>dictionary!{"S"=>"URI","URI"=>Object::string_literal("https://example.org/paper?q=1&v=2"),"IsMap"=>true}});
    let f = d.get_object_mut(first).unwrap().as_dict_mut().unwrap();
    f.set("First", second);
    f.set("Last", second);
    f.set("Count", -1);
    d.objects.insert(
        root,
        Object::Dictionary(
            dictionary! {"Type"=>"Outlines","First"=>first,"Last"=>first,"Count"=>2},
        ),
    );
    d.catalog_mut().unwrap().set("Outlines", root);
    first
}
pub fn render(path: &Path, page: usize) -> Vec<u8> {
    let work = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let out = work.path().join("page.png");
    revayat_scientific::pdf::render_page(path, page, 72, &out).unwrap();
    image::open(out).unwrap().to_rgb8().into_raw()
}
pub fn blank() -> Document {
    let mut d = document(1);
    let id = pages(&d)[0];
    let stream = d.add_object(Stream::new(dictionary! {}, Vec::new()));
    d.get_object_mut(id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Contents", stream);
    d
}
pub fn image_page(d: &mut Document, width: u32, height: u32, raw: Vec<u8>, jpeg: bool) {
    let mut dict = dictionary! {"Type"=>"XObject","Subtype"=>"Image","Width"=>width as i64,"Height"=>height as i64,"BitsPerComponent"=>8,"ColorSpace"=>"DeviceRGB"};
    if jpeg {
        dict.set("Filter", "DCTDecode");
    }
    let image = d.add_object(Stream::new(dict, raw));
    let page = pages(d)[0];
    let mut resources = revayat_scientific::pdf_forms::inherited(d, page, b"Resources")
        .unwrap()
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    resources.set("XObject", dictionary! {"Im1"=>image});
    d.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Resources", resources);
    d.add_to_page_content(
        page,
        Content {
            operations: vec![
                Operation::new("q", vec![]),
                Operation::new(
                    "cm",
                    vec![
                        144.into(),
                        0.into(),
                        0.into(),
                        72.into(),
                        80.into(),
                        250.into(),
                    ],
                ),
                Operation::new("Do", vec![Object::Name(b"Im1".to_vec())]),
                Operation::new("Q", vec![]),
            ],
        },
    )
    .unwrap();
}
pub fn table(d: &mut Document) {
    let page = pages(d)[0];
    let mut ops = Vec::new();
    for x in [30, 180, 330] {
        ops.extend([
            Operation::new("m", vec![x.into(), 340.into()]),
            Operation::new("l", vec![x.into(), 440.into()]),
            Operation::new("S", vec![]),
        ]);
    }
    for y in [340, 390, 440] {
        ops.extend([
            Operation::new("m", vec![30.into(), y.into()]),
            Operation::new("l", vec![330.into(), y.into()]),
            Operation::new("S", vec![]),
        ]);
    }
    for (x, y, text) in [
        (40, 410, "Quantity"),
        (190, 410, "Value"),
        (40, 360, "Temperature"),
        (190, 360, "23.5 C"),
    ] {
        ops.extend([
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new(
                "Tm",
                vec![1.into(), 0.into(), 0.into(), 1.into(), x.into(), y.into()],
            ),
            Operation::new("Tj", vec![Object::string_literal(text)]),
            Operation::new("ET", vec![]),
        ]);
    }
    d.add_to_page_content(page, Content { operations: ops })
        .unwrap();
}
