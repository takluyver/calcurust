**Calcurust** is a Jupyter kernel, written in Rust, implementing a very simple RPN calculator (i.e. `6 7 *` will evaluate to 42).

In the `src/` directory, `messaging.rs` contains most of the functions to communicate with Jupyter, and `main.rs` contains
the RPN implementation and the main functions integrating the functionality.

This was written mainly as a project to learn Rust, but it also serves as an example of implementing a Jupyter kernel
in a language other than Python. I don't intend to add much complexity, so it can remain as a simple example.
