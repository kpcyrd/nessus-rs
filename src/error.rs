use roadrunner;
use parser;

/// A set of errors that can occur
#[derive(Debug)]
pub enum Error {
    Http(roadrunner::Error),
    Status(roadrunner::Response),
    Parser(parser::Error),
    WaitTimeout,
}

impl From<roadrunner::Error> for Error {
    fn from(err: roadrunner::Error) -> Error {
        Error::Http(err)
    }
}

impl From<parser::Error> for Error {
    fn from(err: parser::Error) -> Error {
        Error::Parser(err)
    }
}
