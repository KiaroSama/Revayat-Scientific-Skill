use anyhow::Result;
use std::path::Path;
pub fn pdf(path: &Path) -> Result<()> {
    use lopdf::{Document, Object, Stream, dictionary};
    let mut d = Document::with_version("1.7");
    let pages = d.new_object_id();
    let stream = d.add_object(Stream::new(dictionary! {}, vec![]));
    let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![Object::from(0),Object::from(0),Object::from(220),Object::from(330)],"Contents"=>stream,"Resources"=>dictionary!{}});
    d.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let catalog = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    d.trailer.set("Root", catalog);
    d.save(path)?;
    Ok(())
}
