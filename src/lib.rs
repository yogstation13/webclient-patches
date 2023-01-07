#![forbid(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, c_void};
use std::{collections::hash_map::HashMap};
use std::cell::RefCell;

use byond_export::byond_return;
use detour::RawDetour;
use skidscan::{Signature, signature};

// I have literally never touched rust before so don't yell at me too hard please
// I only used rust because otherwise people would yell at me like "ree why didn't you use rust"
// also the compiling tools are less ass, because otherwise this is literally fitting a
// square peg (low level ass hacky shit) into a round hole (rust)

#[macro_use]
mod byond_export;

thread_local! {
	static TOKEN_MAP: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
	static CLIENT_MAP: RefCell<HashMap<u16, String>> = RefCell::new(HashMap::new());
}
static mut LOADED : bool = false;

byond_fn!(
	fn set_webclient_auth(token, info) {
		if let Err(e) = init_module() {
			return Some(e);
		}
		TOKEN_MAP.with(|cell| {
			let mut map = cell.borrow_mut();
			map.insert(String::from(token), String::from(info));
		});
		Some("")
	}
);

byond_fn!(
	fn remove_webclient_patches() {
		unsafe {
			if !LOADED {return Some("");}
			LOADED = false;
		}
		undo_replacements();
		Some("")
	}
);

struct SigOffset(Signature, u32);

static mut ORIG_REPLACEMENTS : Vec<(*mut u32, u32)> = vec![];
static mut DETOURS : Vec<RawDetour> = vec![];

unsafe fn extract_function_call(sig : SigOffset, module : &str) -> Result<u32, ()> {
	unsafe {
		if let Ok(ptr) = sig.0.scan_module(module) {
			Ok(*(((ptr as u32) + sig.1) as *mut u32) + (ptr as u32 + sig.1) + 4)
		} else {
			Err(())
		}
	}
}
unsafe fn replace_function_call(sig : SigOffset, module : &str, replacement_ptr : u32) -> Result<(), ()> {
	unsafe {
		if let Ok(ptr) = sig.0.scan_module(module) {
			let call_ptr = (ptr as u32 + sig.1) as *mut u32;
			if let Err(_) = region::protect(call_ptr, 4, region::Protection::READ_WRITE_EXECUTE) {
				return Err(());
			}
			ORIG_REPLACEMENTS.push((call_ptr, *call_ptr));
			*call_ptr = replacement_ptr - (call_ptr as u32) - 4;
			Ok(())
		} else {
			Err(())
		}
	}
}
fn undo_replacements() {
	unsafe {
		ORIG_REPLACEMENTS.reverse();
		for (ptr, orig) in ORIG_REPLACEMENTS.iter() {
			**ptr = *orig;
		}
		ORIG_REPLACEMENTS.clear();
		DETOURS.reverse();
		for detour in DETOURS.iter() {
			let _ = detour.disable();
		}
		DETOURS.clear();
	}
}

#[cfg(windows)]
const BYONDCORE: &str = "byondcore.dll";
#[cfg(unix)]
const BYONDCORE: &str = "libbyond.so";

fn init_module() -> Result<(), &'static str> {
	unsafe {
		if LOADED { return Ok(()); }
		LOADED = true;

		#[cfg(windows)]
		let sig_short = SigOffset(
			signature!("8d 45 e0 8b cf 50 53 e8 ?? ?? ?? ?? b8 ff bf 00 00"),
			8
		);
		#[cfg(windows)]
		let sig_write_flags_delete = SigOffset(
			signature!("a9 00 80 00 00 75 ?? ff 45 ?? 8b cf 53 6a 00 e8 ?? ?? ?? ?? 0f b6 4e"),
			16
		);
		#[cfg(windows)]
		let sig_write_flags_modify = SigOffset(
			signature!("53 89 45 e0 e8 ?? ?? ?? ?? 8b 4e 24 0f b6 46 20 81 e1 ff ff ff 00"),
			5
		);
		#[cfg(windows)]
		let sig_handle_hub_cert = signature!(
			"55 8b ec 6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 f0 53 56 57 50 8d 45 f4 64 a3 ?? ?? ?? ?? 8b 75 10 8b 7d 0c 56"
		);
		#[cfg(windows)]
		let sig_receive_login_key = signature!(
			"55 8b ec 6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 f0 56 57 50 8d 45 f4 64 a3 ?? ?? ?? ?? 8b 45 0c 8d 8d 40 fb ff ff 8b 75 08 0f b7 f8"
		);
		#[cfg(unix)]
		let sig_short = SigOffset(
			signature!("89 54 24 08 89 44 24 04 89 34 24 e8 ?? ?? ?? ?? 66 81 63 38 ff bf 8b 5d c4 85 db"),
			12
		);
		#[cfg(unix)]
		let sig_write_flags_delete = SigOffset(
			signature!("89 34 24 e8 ?? ?? ?? ?? 89 7c 24 08 0f b6 43 20 8b 53 24 89 34 24 c1 e0 18 81 e2 ff ff ff 00"),
			4
		);
		#[cfg(unix)]
		let sig_write_flags_modify = SigOffset(
			signature!("8b 56 04 89 44 24 04 89 7c 24 08 89 34 24 89 55 e0 e8 ?? ?? ?? ?? 89 7c 24 08 0f b6 43 20 8b 53 24 89 34 24"),
			18
		);
		#[cfg(unix)]
		let sig_handle_hub_cert = signature!(
			"55 89 e5 81 ec d8 04 00 00 0f b7 45 10 89 5d f4 0f b6 5d 08 89 75 f8"
		);
		#[cfg(unix)]
		let sig_receive_login_key = signature!(
			"55 89 e5 57 56 89 c6 53 89 d3 81 ec dc 04 00 00 0f b7 db 8d 45 a8 c7 45 e0 00 00 00 00 c7 45 dc 00 00 00 00 89 04 24"
		);

		// This part patches BYOND's code which encodes modified movables into network messages for the webclient.
		// The way the code works is that it writes a byte into the message, holding onto a pointer to that byte.
		// Later, after writing the various changes, this flag byte is updated. Unfortunately this is a short and not
		// a byte like before, so this clobbers the least significant byte of the movable's ID. What this changes is that
		// the flags is now reserved 2 bytes, to fit the expanded flags to include the vis_contents flag.
		// This will unfortunately break the official webclient even more than it's already broken.

		// This is clearly a case of "Lummox started working on it and then didn't bother to finish"
		
		if let Ok(short_ptr) = extract_function_call(sig_short, BYONDCORE) {

			if let Err(_) = replace_function_call(sig_write_flags_delete, BYONDCORE, short_ptr) {
				return Err("Couldn't find delete-atom flags write call");
			}
			if let Err(_) = replace_function_call(sig_write_flags_modify, BYONDCORE, short_ptr) {
				return Err("Couldn't find modify-atom flags write call");
			}

		} else {
			return Err("Couldn't find short ptr!");
		}

		// This part hooks the login code so that we can actually login!
		// This is necessary because the default BYOND webclient loginy thing is full of problems like:
		// - Being completely fucked over by Cloudflare
		// - Being completely incompatible with HTTPS
		//   - Basically, BYOND's webclient iframe thingy will break horribly if you give it an https thingy
		//   - It's worse than that: BYOND's iframe thingy will also break if you give it an http thingy
		//     - That's cause browsers don't like it when you mix http and https
		//   - Even if I could get that to work, yogstation has HSTS so that's a no go
		// - Requiring you to put your thing inside of BYOND's iframe bullshit
		//   - This solution might make lummox mad at me because it bypasses ads.

		if let Ok(handle_hub_cert) = sig_handle_hub_cert.scan_module(BYONDCORE) {
			let hook = RawDetour::new(handle_hub_cert as *const (), handle_hub_cert_hook as *const ())
				.map_err(|_| "Couldn't detour handle_hub_cert")?;
			hook.enable()
				.map_err(|_| "Couldn't enable detour for handle_hub_cert")?;
			HANDLE_HUB_CERT_ORIGINAL = Some(std::mem::transmute(hook.trampoline()));
			DETOURS.push(hook);
		} else {
			return Err("Couldn't find handle_hub_cert")
		}

		if let Ok(receive_login_key) = sig_receive_login_key.scan_module(BYONDCORE) {
			let hook = RawDetour::new(receive_login_key as *const (), _receive_login_key_hook_c as *const ())
				.map_err(|_| "Couldn't detour receive_login_key")?;
			hook.enable()
				.map_err(|_| "Couldn't enable detour for receive_login_key")?;
			_receive_login_key_orig = std::mem::transmute(hook.trampoline());
			DETOURS.push(hook);
		} else {
			return Err("Couldn't find receive_login_key")
		}
		
		Ok(())
	}
}

//static mut RECEIVE_LOGIN_KEY_ORIGINAL: Option<extern "C" fn(*const ByondNetMessage, u16) -> c_void> = None;

// why the ever living fuck do I have to put underscores on my shit. why do I get linker errors when there's
// no underscores. what the fuck.
// why the fuck do I need a shitty ass c file just to use regparm3?
// I wish I had just written this shit in c
extern "C" {
	static mut _receive_login_key_orig : *const c_void;
	//static _receive_login_key_hook_c : *const c_void;
	fn _receive_login_key_hook_c(message : *const ByondNetMessage, client_id : u16) -> c_void;
	fn _receive_login_key_orig_c(message : *const ByondNetMessage, client_id : u16) -> c_void;
}

#[no_mangle]
extern "C" fn receive_login_key_hook(message : *const ByondNetMessage, client_id : u16) -> c_void {
	CLIENT_MAP.with(|cell| {
		let mut map = cell.borrow_mut();
		map.remove(&client_id);
	});
	
	let mut ptr : isize = 0;
	let token = unsafe { (*message).read_string(&mut ptr) };
	TOKEN_MAP.with(|cell| {
		let mut map = cell.borrow_mut();
		if let Some(key_info) = map.remove(&token) {
			CLIENT_MAP.with(|cell| {
				let mut map = cell.borrow_mut();
				map.insert(client_id, key_info);
			});
		}
	});
	//unsafe { RECEIVE_LOGIN_KEY_ORIGINAL.unwrap()(message, client_id) }
	unsafe { _receive_login_key_orig_c(message, client_id) }
}

static mut HANDLE_HUB_CERT_ORIGINAL : Option<extern "C" fn(bool, *const c_char, u16) -> c_void> = None;

#[no_mangle]
extern "C" fn handle_hub_cert_hook(in_is_valid : bool, in_cert : *const c_char, client_id : u16) -> c_void {
	let looked_up = CLIENT_MAP.with(|cell| {
		let mut map = cell.borrow_mut();
		map.remove(&client_id)
	});
	let (is_valid, cert) = match looked_up {
		Some(info) => (true, byond_return(Some(info.into_bytes()))),
		_ => (in_is_valid, in_cert)
	};
	unsafe { HANDLE_HUB_CERT_ORIGINAL.unwrap()(is_valid, cert, client_id)}
}

#[repr(C)]
struct ByondNetMessage {
	msgtype : u16,
	error_flags : u16,
	length : isize,
	unk : u32,
	data : *mut u8
}

impl ByondNetMessage {
	fn read_string(&self, ptr : &mut isize) -> String {
		if self.length <= *ptr {return "".to_owned()}
		let mut out_vec : Vec<u8> = Vec::new();
		unsafe {
			while *ptr < self.length {
				let this_ptr = self.data.offset(*ptr);
				if *this_ptr == 0 {*ptr += 1; break;}
				out_vec.push(*this_ptr);
				*ptr += 1;
			}
		}
		return match String::from_utf8(out_vec) {
			Ok(str) => str,
			Err(_) => "".to_owned()
		}
	}
}

// So there, is this shitty little DLL really *that much better* just because I wrote it in rust?

// is it?

#[cfg(not(target_pointer_width = "32"))]
compile_error!("this piece of shit must be compiled for a 32-bit target");
