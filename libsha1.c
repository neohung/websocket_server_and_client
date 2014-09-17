#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "sha1.h"
 
#undef BIG_ENDIAN_HOST
typedef unsigned int u32 ;

typedef struct {
    u32  h0 ,h1 , h2, h3 ,h4 ;
    u32  nblocks ;
    unsigned char buf[ 64 ];
    int  count ;
} SHA1_CONTEXT ;

// 定義旋轉函數 rol
#if defined(__GNUC__) && defined(__i386__)
     static inline u32
    rol ( u32 x , int n )
     {
         __asm__ ( "roll %%cl,%0" :"=r" (x ): "0" (x ),"c" ( n));
         return x;
     }
#else
     #define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

void sha1_init ( SHA1_CONTEXT *hd )
{
    //printf("%s\n", "do_sha1_init");
    hd ->h0 = 0x67452301 ;
    hd ->h1 = 0xefcdab89 ;
    hd ->h2 = 0x98badcfe ;
    hd ->h3 = 0x10325476 ;
    hd ->h4 = 0xc3d2e1f0 ;
    hd ->nblocks = 0 ;
    hd ->count = 0 ;
}

static void transform ( SHA1_CONTEXT * hd, unsigned char *data )  {
    //printf("%s\n", "do_transform");
    u32 a ,b , c, d ,e ,tm ;  
    u32 x [16 ];
    a = hd -> h0;  
    b = hd -> h1;  
    c = hd -> h2;  
    d = hd -> h3;  
    e = hd -> h4;
    unsigned char * ptest ;
    ptest =   ( unsigned char *) data ;
#ifdef BIG_ENDIAN_HOST 
    //如果是 BIG_ENDIAN_HOST 直接拷貝64bytes(512bits) 即可
    memcpy ( x , data, 64 ); 
#else 
    {
      //data原來資料是 61 62 63 80 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
      //0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 18 
      //如果是 LITTLE_ENDIAN_HOST
      //直接使用 msmcpy(x,data,64); 會變成
      //x[0]=0x80636261, x[1]=0...x[15]=0x18000000
      //但是我們希望 x[] 是BIG_ENDIAN 格式
      //所以每 4bytes 需要倒著寫入才能變成 BIG_ENDIAN型式
        int i;  
        unsigned char *p2 ; 
        // 指針p2 指向 x[16],
        // 分成x[0]=0x61626380, x[1]=0x00000000,...x[15]=0x000000018
        for (i = 0, p2 =(unsigned char *) x; i < 16 ; i ++, p2 += 4 )  
        {  
            p2 [ 3] = *data ++;  
            p2 [ 2] = *data ++;  
            p2 [ 1] = *data ++;  
            p2 [ 0] = *data ++;  
        }

    
    } 
#endif    
    #define K1  0x5A827999L 
    #define K2  0x6ED9EBA1L 
    #define K3  0x8F1BBCDCL 
    #define K4  0xCA62C1D6L 
    #define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) ) 
    #define F2(x,y,z)   ( x ^ y ^ z ) 
    #define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) ) 
    #define F4(x,y,z)   ( x ^ y ^ z )
    //對 i=16~79, w[i] := (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
    #define M(i) ( tm=x[i&0x0f]^x[(i-14)&0x0f]^x[(i-8)&0x0f]^x[(i-3)&0x0f] , (x[i&0x0f]=rol(tm,1)) )    
    // e := (a leftrotate 5) + f + e + k + w[i]
    // b := b leftrotate 30
    // each time right rotate 1 bit
    #define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 ) + f( b, c, d ) + k + m; b = rol( b, 30 );} while(0) 
    //0~19 using F1 
    R ( a , b, c , d , e , F1, K1 , x [ 0 ] );  
    R ( e , a, b , c , d , F1, K1 , x [ 1 ] );  
    R ( d , e, a , b , c , F1, K1 , x [ 2 ] );  
    R ( c , d, e , a , b , F1, K1 , x [ 3 ] );  
    R ( b , c, d , e , a , F1, K1 , x [ 4 ] );  
    R ( a , b, c , d , e , F1, K1 , x [ 5 ] );  
    R ( e , a, b , c , d , F1, K1 , x [ 6 ] );  
    R ( d , e, a , b , c , F1, K1 , x [ 7 ] );  
    R ( c , d, e , a , b , F1, K1 , x [ 8 ] );  
    R ( b , c, d , e , a , F1, K1 , x [ 9 ] );  
    R ( a , b, c , d , e , F1, K1 , x [ 10] ); 
    R ( e , a, b , c , d , F1, K1 , x [ 11] ); 
    R ( d , e, a , b , c , F1, K1 , x [ 12] ); 
    R ( c , d, e , a , b , F1, K1 , x [ 13] ); 
    R ( b , c, d , e , a , F1, K1 , x [ 14] ); 
    R ( a , b, c , d , e , F1, K1 , x [ 15] ); 
    R ( e , a, b , c , d , F1, K1 , M ( 16) ); 
    R ( d , e, a , b , c , F1, K1 , M ( 17) ); 
    R ( c , d, e , a , b , F1, K1 , M ( 18) ); 
    R ( b , c, d , e , a , F1, K1 , M ( 19) );
    //20~39 using F2 
    R ( a , b, c , d , e , F2, K2 , M ( 20) ); 
    R ( e , a, b , c , d , F2, K2 , M ( 21) ); 
    R ( d , e, a , b , c , F2, K2 , M ( 22) ); 
    R ( c , d, e , a , b , F2, K2 , M ( 23) ); 
    R ( b , c, d , e , a , F2, K2 , M ( 24) ); 
    R ( a , b, c , d , e , F2, K2 , M ( 25) ); 
    R ( e , a, b , c , d , F2, K2 , M ( 26) ); 
    R ( d , e, a , b , c , F2, K2 , M ( 27) ); 
    R ( c , d, e , a , b , F2, K2 , M ( 28) ); 
    R ( b , c, d , e , a , F2, K2 , M ( 29) ); 
    R ( a , b, c , d , e , F2, K2 , M ( 30) ); 
    R ( e , a, b , c , d , F2, K2 , M ( 31) ); 
    R ( d , e, a , b , c , F2, K2 , M ( 32) ); 
    R ( c , d, e , a , b , F2, K2 , M ( 33) ); 
    R ( b , c, d , e , a , F2, K2 , M ( 34) ); 
    R ( a , b, c , d , e , F2, K2 , M ( 35) ); 
    R ( e , a, b , c , d , F2, K2 , M ( 36) ); 
    R ( d , e, a , b , c , F2, K2 , M ( 37) ); 
    R ( c , d, e , a , b , F2, K2 , M ( 38) ); 
    R ( b , c, d , e , a , F2, K2 , M ( 39) ); 
    //40~59 using F3 
    R ( a , b, c , d , e , F3, K3 , M ( 40) ); 
    R ( e , a, b , c , d , F3, K3 , M ( 41) ); 
    R ( d , e, a , b , c , F3, K3 , M ( 42) ); 
    R ( c , d, e , a , b , F3, K3 , M ( 43) ); 
    R ( b , c, d , e , a , F3, K3 , M ( 44) ); 
    R ( a , b, c , d , e , F3, K3 , M ( 45) ); 
    R ( e , a, b , c , d , F3, K3 , M ( 46) ); 
    R ( d , e, a , b , c , F3, K3 , M ( 47) ); 
    R ( c , d, e , a , b , F3, K3 , M ( 48) ); 
    R ( b , c, d , e , a , F3, K3 , M ( 49) ); 
    R ( a , b, c , d , e , F3, K3 , M ( 50) ); 
    R ( e , a, b , c , d , F3, K3 , M ( 51) ); 
    R ( d , e, a , b , c , F3, K3, M( 52 ) );  
    R ( c , d, e , a , b , F3, K3 , M ( 53) ); 
    R ( b , c, d , e , a , F3, K3 , M ( 54) ); 
    R ( a , b, c , d , e , F3, K3 , M ( 55) ); 
    R ( e , a, b , c , d , F3, K3 , M ( 56) ); 
    R ( d , e, a , b , c , F3, K3 , M ( 57) ); 
    R ( c , d, e , a , b , F3, K3 , M ( 58) ); 
    R ( b , c, d , e , a , F3, K3 , M ( 59) ); 
    //60~79 using F4 
    R ( a , b, c , d , e , F4, K4 , M ( 60) ); 
    R ( e , a, b , c , d , F4, K4 , M ( 61) ); 
    R ( d , e, a , b , c , F4, K4 , M ( 62) ); 
    R ( c , d, e , a , b , F4, K4 , M ( 63) ); 
    R ( b , c, d , e , a , F4, K4 , M ( 64) ); 
    R ( a , b, c , d , e , F4, K4 , M ( 65) ); 
    R ( e , a, b , c , d , F4, K4 , M ( 66) ); 
    R ( d , e, a , b , c , F4, K4 , M ( 67) ); 
    R ( c , d, e , a , b , F4, K4 , M ( 68) ); 
    R ( b , c, d , e , a , F4, K4 , M ( 69) ); 
    R ( a , b, c , d , e , F4, K4 , M ( 70) ); 
    R ( e , a, b , c , d , F4, K4 , M ( 71) ); 
    R ( d , e, a , b , c , F4, K4 , M ( 72) ); 
    R ( c , d, e , a , b , F4, K4 , M ( 73) ); 
    R ( b , c, d , e , a , F4, K4 , M ( 74) ); 
    R ( a , b, c , d , e , F4, K4 , M ( 75) ); 
    R ( e , a, b , c , d , F4, K4 , M ( 76) ); 
    R ( d , e, a , b , c , F4, K4 , M ( 77) ); 
    R ( c , d, e , a , b , F4, K4 , M ( 78) ); 
    R ( b , c, d , e , a , F4, K4 , M ( 79) ); 
 
    /* Update chaining vars */ 
    hd ->h0 += a;  
    hd ->h1 += b;  
    hd ->h2 += c;  
    hd ->h3 += d;  
    hd ->h4 += e;  
}

void sha1_write ( SHA1_CONTEXT *hd , unsigned char * buf , int len )
{
    //printf("%s\n", "do_sha1_write");
    if ( hd-> count == 64 ){
        // 當hd->count=64bytes 表示 hd->buf有 512bits 了開始transform
        transform ( hd, hd ->buf );  
        hd -> count = 0 ;  
        hd -> nblocks ++; 
    }
    if ( !len )  
        return ; 
    if ( hd-> count ){
        //hd->count 有值時表示是 msg的最後一個 chunk, 這時候就直接 hd->buf拷貝了來自 buf 的資料    
        for ( ; len && hd ->count < 64 ; len-- ) {
            hd -> buf[ hd ->count ++] = * buf ++;
        }
        if ( ! len )
            return ;
    }
    // 一開始 hd->count == 0 執行以下程式
    // 如果 len >=64 則直接拿msg 的該 64bytes去做 transform(hd,buf) 來更新hd->h0 ~ hd->h4
     while ( len >= 64 ) {
        transform ( hd, buf ); 
        hd -> count = 0 ;  
        hd -> nblocks ++; 
        len -= 64 ;  
        buf += 64 ;  
     }
     //hd->count < 64時表示是 msg 的最後一個 chunk,這時候就直接 hd->buf 拷貝了來自 buf的資料
     for (; len && hd -> count < 64 ; len--){       
        hd -> buf[ hd ->count ++] = * buf ++;   
     }
}

static void sha1_final (SHA1_CONTEXT * hd)
{
    //printf("%s\n", "do_sha1_final");
    //lsb,msb存放 msg 長度
    u32 t , msb , lsb;  
    unsigned char * p ; 
    //清空 hd->buf
    sha1_write (hd , NULL , 0 );
    t = hd -> nblocks ;   
   
    lsb = t << 6 ;
    msb = t >> 26 ;  
  
    /* add the count */ 
    t = lsb ;  
    if ( (lsb += hd-> count ) < t )  
        msb ++;  
    /* multiply by 8 to make a bit count */ 
    //
    t = lsb ;  
    //lsb以 bit 為單位所以 += hd->count * 8
    lsb <<= 3 ; 
    msb <<= 3 ; 
    msb |= t >> 29 ;  
    if ( hd ->count < 56 ) { /* enough room */  
        // 訊息的最後要補 1,就是 0x80, 如果訊息小於 56 (即 56*8=448bit)
        hd -> buf[ hd ->count ++] = 0x80 ; /* pad */  
        while ( hd -> count < 56 ) 
            hd -> buf[ hd ->count ++] = 0 ;   /* pad */  
    } 
    else {
        hd -> buf[ hd ->count ++] = 0x80 ; /* pad character */  
        while ( hd -> count < 64 ) 
            hd -> buf[ hd ->count ++] = 0 ;  
        sha1_write ( hd, NULL, 0 );   /* flush */ ;  
        memset ( hd-> buf , 0 , 56 ); /* fill next block with zeroes */  
    }
    //448bit之後補上 msg 長度值, 以 bit為單位
    hd ->buf [ 56] = msb >> 24 ; 
    hd ->buf [ 57] = msb >> 16 ; 
    hd ->buf [ 58] = msb >>  8 ; 
    hd ->buf [ 59] = msb       ;  
    hd ->buf [ 60] = lsb >> 24 ; 
    hd ->buf [ 61] = lsb >> 16 ; 
    hd ->buf [ 62] = lsb >>  8 ; 
    hd ->buf [ 63] = lsb       ;
/*
    int i=0;
    while( i < 64 ){
        printf("%x ", hd->buf[i++]);
    }
*/  
    //做最後一次的 transform
    transform ( hd , hd-> buf );

       p = hd-> buf ; 

#ifdef BIG_ENDIAN_HOST
    //buf = hash = h0 append h1 append h2 append h3 append h4 
    #define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0) 
#else  //LITTLE_ENDIAN 
    #define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16; *p++ = hd->h##a >> 8; *p++ = hd->h##a; }while(0) 
#endif 
//hd->buf = hd->h0
X (0 );  
//hd->buf = hd->buf append hd->h1
X (1 );  
//hd->buf = hd->buf append hd->h2
X (2 );  
//hd->buf = hd->buf append hd->h3
X (3 );  
//hd->buf = hd->buf append hd->h4
X (4 );  
#undef X     
}

// 給message 跟 len(message)傳回 20bytes(160bits) 的sha1 值
unsigned char * getsha1 (unsigned char * message , int length )
{
    unsigned char * res = malloc(20);
    memset(res,0,20);
    SHA1_CONTEXT s ;
    sha1_init (&s );
    sha1_write ( & s , message , length );
    sha1_final (&s );
    int i ;
    for ( i= 0 ; i < 20 ; i++)  
    { 
        res[i]= s.buf[i]; 
    } 
    //printf("[%s]\n", res);
    return res ;
}
unsigned char * getsha1convertToString(unsigned char * message , int length )
{
    unsigned char * res = malloc ( 40);
    memset(res,0,40);
    SHA1_CONTEXT s ;
    sha1_init (&s );
    sha1_write ( & s , message , length );
    sha1_final (&s );
    int i ;
    for ( i= 0 ; i < 20 ; i++)
    {
        snprintf (res,4 ,"%02x" ,s.buf[ i]);
        res=res+2;
    }
    res=res-40;
    //printf("[%s]\n", res);
    return res ;
}
/*
int main(int argc, char const *argv[])
{

#if defined(__GNUC__)
     printf("define __GNUC__\n");
#endif
#if defined(__i386__)
     printf("define __i386__\n");
#endif
#if defined(BIG_ENDIAN_HOST)
     printf("define BIG_ENDIAN_HOST\n");
#endif

     printf("\n%s\n","'abc'shoule be \na9993e364706816aba3e25717850c26c9cd0d89d" );
     printf ("\n%s\n", getsha1("abc", 3));
     return 0;
}

*/
