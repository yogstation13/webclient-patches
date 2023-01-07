#ifdef _WIN32
#define REGPARM3
#else
#define REGPARM3 __attribute__((regparm(3)))
#endif

void receive_login_key_hook(void* a, short b);
void REGPARM3 _receive_login_key_hook_c(void* a, short b) {
	receive_login_key_hook(a, b);
}

void (REGPARM3 *_receive_login_key_orig)(void* a, short b);
void _receive_login_key_orig_c(void* a, short b) {
	_receive_login_key_orig(a, b);
}
