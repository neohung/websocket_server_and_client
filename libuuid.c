#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static char is_init_uuid = 1;
char *random_uuid()
{
    if (is_init_uuid){
	srand( time(NULL) );
	is_init_uuid = 0;
    }
    const char *c = "89ab";
    char *p = (char *)malloc(37);
    char *return_uuid = p;
    int n;
    for( n = 0; n < 16; ++n )
    {
        int b = rand()%255;
        switch( n )
        {
            case 6:
                sprintf(p, "4%x", b%15 );
                break;
            case 8:
                sprintf(p, "%c%x", c[rand()%strlen(c)], b%15 );
                break;
            default:
                sprintf(p, "%02x", b );
                break;
        }
        p += 2;
        switch( n )
        {
            case 3:
            case 5:
            case 7:
            case 9:
                *p++ = '-';
                break;
        }
    }
    return return_uuid;
}
/*
void main()
{
	char*buf[37];
	printf("%s\n",random_uuid());
}
*/
