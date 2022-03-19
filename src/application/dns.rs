use std::fmt::{Display, Formatter};
use std::ops::Deref;
use prettytable::{format, table, row, cell};
use crate::util::tou16;

#[derive(Debug)]
pub struct DNSQuery {
    id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority_rr: u16,
    additional_rr: u16,
    query_requests: Vec<DNSQueryRequest>,
    query_answers: Vec<DNSQueryAnswer>
}

#[derive(Debug)]
struct DNSQueryRequest {
    name: String,
    query_type: u16,
    query_class: u16
}

#[derive(Debug)]
struct DNSQueryAnswer {
    name: u16,
    answer_type: u16,
    class: u16,
    ttl: u16,
    rdlength: u16,
}

impl Display for DNSQueryRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut table = table!(
            ["name", self.name],
            ["type", self.query_type],
            ["class", self.query_class]
        );

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(10, 10);

        writeln!(f, "{}", table);
        Ok(())
    }
}

impl DNSQueryRequest {
    fn from(data: &[u8]) -> (Self, &[u8]) {
        let mut name = String::new();
        let mut length = 0;
        while data[length] != 0 {
            name += String::from_utf8_lossy(&data[length+1 as usize..(data[length]+length as u8+1) as usize]).deref();
            name += ".";
            length += (data[length]+1) as usize;
        }
        (Self {
            name,
            query_type: tou16(&data[length+1..length+3]),
            query_class: tou16(&data[length+3..length+5]),
        }, &data[length+5..])
    }
}

impl From<&[u8]> for DNSQuery {
    fn from(data: &[u8]) -> Self {
        let mut data_pointer = &data[12..];
        let mut answers = Vec::new();
        for i in 0..(tou16(&data[4..6])) as usize {
            let combo = DNSQueryRequest::from(data_pointer);
            answers.push(combo.0);
            data_pointer = combo.1;
        }

        Self {
            id: tou16(&data[0..2]),
            flags: tou16(&data[2..4]),
            questions: tou16(&data[4..6]),
            answers: tou16(&data[6..8]),
            authority_rr: tou16(&data[8..10]),
            additional_rr: tou16(&data[10..12]),
            query_requests: answers,
            query_answers: vec![]
        }
    }
}

impl Display for DNSQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {

        let mut table = table!(
            ["id", format!("{:X}", self.id)],
            ["flags", format!("{:b}", self.flags)],
            ["questions", self.questions],
            ["answers", self.answers],
            ["authority_rr", self.authority_rr],
            ["additional_rr", self.additional_rr]
        );
        table.set_format(*format::consts::FORMAT_CLEAN);
        table.get_format().padding(5, 5);
        writeln!(f, "{}", table).unwrap();
        for request in self.query_requests.iter().enumerate() {
            writeln!(f, "QUERY REQUEST {}", request.0);
            writeln!(f, "{}", request.1).unwrap();
        }
        Ok(())
    }
}
