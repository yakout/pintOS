#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{

  	pid_t child = exec ("child-simple");
  	printf ("wait(exec()) = %d", wait (child));
  	printf ("wait(exec()) = %d", wait (child));

  	return EXIT_SUCCESS;
}
	