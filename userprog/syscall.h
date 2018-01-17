#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

enum 
  {
    PARM_ZERO,                   
    PARM_ONE,                   
    PARM_TWO,                   
    PARM_THREE,                   
  };



void syscall_init (void);

#endif /* userprog/syscall.h */
