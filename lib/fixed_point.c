#include "fixed_point.h"


struct fixed_point int_to_fixedpoint(int number){
	struct fixed_point result;
	result.value=number*(2**14);
	return result;

}




















