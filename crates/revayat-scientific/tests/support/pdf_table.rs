//! Shared two-page signed-decimal grid fixture, upright despite stored rotation.
use lopdf::{
    Document, Object,
    content::{Content, Operation},
};
pub fn signed_table() -> Document {
    let mut d = super::common::document(2);
    for (index, page) in super::common::pages(&d).into_iter().enumerate() {
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new(
                "Tm",
                vec![
                    0.into(),
                    1.into(),
                    (-1).into(),
                    0.into(),
                    10.into(),
                    10.into(),
                ],
            ),
            Operation::new(
                "Tj",
                vec![Object::string_literal("Rotated margin outside grid")],
            ),
            Operation::new("ET", vec![]),
            Operation::new("q", vec![]),
        ];
        if index == 1 {
            // Counter-rotate content so both pages display the same upright table.
            ops.push(Operation::new(
                "cm",
                vec![
                    0.into(),
                    1.into(),
                    (-1).into(),
                    0.into(),
                    400.into(),
                    0.into(),
                ],
            ));
        }
        for x in [30, 180, 330] {
            ops.extend([
                Operation::new("m", vec![x.into(), 190.into()]),
                Operation::new("l", vec![x.into(), 340.into()]),
                Operation::new("S", vec![]),
            ]);
        }
        for y in [190, 240, 290, 340] {
            ops.extend([
                Operation::new("m", vec![30.into(), y.into()]),
                Operation::new("l", vec![330.into(), y.into()]),
                Operation::new("S", vec![]),
            ]);
        }
        for (row, cells) in [
            ["Quantity", "Value"],
            ["Temperature", "+23.5 C"],
            ["Potential", "-0.25 mV"],
        ]
        .into_iter()
        .enumerate()
        {
            for (column, text) in cells.into_iter().enumerate() {
                ops.extend([
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
                    Operation::new(
                        "Tm",
                        vec![
                            1.into(),
                            0.into(),
                            0.into(),
                            1.into(),
                            (40 + column as i64 * 150).into(),
                            (310 - row as i64 * 50).into(),
                        ],
                    ),
                    Operation::new("Tj", vec![Object::string_literal(text)]),
                    Operation::new("ET", vec![]),
                ]);
            }
        }
        ops.push(Operation::new("Q", vec![]));
        d.change_page_content(page, Content { operations: ops }.encode().unwrap())
            .unwrap();
        if index == 1 {
            d.get_object_mut(page)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("Rotate", 90);
        }
    }
    d
}
