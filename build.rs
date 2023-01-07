fn main() {
	
	cc::Build::new()
		.file("src/regparm3_bullshit.c")
		.compile("hooks");
}
