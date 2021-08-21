#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main()
{
    char filename[] = "./tests/src.txt";
    uint8_t buffer[16];
    FILE *fh;
    uint8_t r;

    /* open the file */
    fh = fopen(filename,"r");
    if(!fh)
    {
        fprintf(stderr,"Unable to open %s\n",filename);
        return(1);
    }

    memset(buffer, 0, 16);
    r = fread( buffer, sizeof(uint8_t), 16, fh );

    for (size_t i = 0; i < 16; i++)
    {
        printf("%c\n", buffer[i]);
    }
    printf("\n");
    

    fclose(fh);
    return(0);
}