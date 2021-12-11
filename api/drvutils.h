#pragma once

void start_driver()
{
	driver().handle_driver();

	if (!driver().is_loaded())
		mmap_driver();

	driver().handle_driver();
	if (!driver().is_loaded()) {
		printf(("unknown error !!")); Sleep(2000); exit(43);
	}
}
