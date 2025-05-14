`from` and `to` define what portion of the body to get:

| `from`    | `to`      | Start                                 | End                                  |
| --------- | --------- | ------------------------------------- | ------------------------------------ |
| `None`    | `None`    | start of the body                     | end of the body                      |
| `Some(x)` | `None`    | `x` bytes from the start of body      | end of the body                      |
| `Some(x)` | `Some(y)` | `x` bytes from the start of the body  | `y` bytes from the start of the body |
| `None`    | `Some(y)` | `y` bytes from the _end_ of the body  | end of the body                      |

The range is only respected if the length of the body is known before this call *and* the
range is valid. If the range is invalid _or_ the length of the body is not known, the entire body is returned.

