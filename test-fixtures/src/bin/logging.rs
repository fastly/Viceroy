use fastly::log::Endpoint;
use std::io::Write;

fn main() {
    let mut mib = Endpoint::from_name("mib");
    let mut inigo = Endpoint::from_name("inigo");

    inigo.write_all(b"Who are you?").unwrap();
    mib.write_all(b"No one of consequence.").unwrap();
    inigo.write_all(b"I must know.").unwrap();
    mib.write_all(b"Get used to disappointment.").unwrap();

    mib.write_all(b"There is something\nI ought to tell you.")
        .unwrap();
    inigo.write_all(b"Tell me.\n\n").unwrap();
    mib.write_all(b"I'm not left-handed either.").unwrap();
    inigo.write_all(b"\n").unwrap(); // this event should be dropped
    inigo.write_all(b"O_O\n").unwrap();

    println!("logging from stdout");
    eprintln!("logging from stderr");
    println!(""); // this should be dropped
    eprintln!(""); // this should be dropped

    // showcase line buffering on stdout
    print!("log line terminates on flush");
    std::io::stdout().flush().unwrap();
    print!("newline completes");
    println!(" a log line");

    // showcase no buffering on stderr
    eprint!("log line terminates on flush");
    std::io::stderr().flush().unwrap();
    eprint!("log line terminates");
    eprint!("on each write");

    assert!(Endpoint::try_from_name("stdout").is_err());
    assert!(Endpoint::try_from_name("stderr").is_err());
    assert!(Endpoint::try_from_name("STDOUT").is_err());
}
