// armv5_stratum_miner.c
// Mini Stratum v1 (POC) pour ARMv5 avec :
// - Reconnexion auto (backoff 1s -> 10s)
// - Affichage du hashrate toutes les 10s
// Limitations : pas de SSL, JSON naïf, mono-thread.

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); fprintf(stderr, "\n"); va_end(ap);
    exit(1);
}
static void warnx(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); fprintf(stderr, "\n"); va_end(ap);
}

/* ========================= SHA-256 ========================= */
typedef struct { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t idx; } sha256_ctx;
static inline uint32_t ROR(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
static void sha256_init(sha256_ctx *ctx){
    static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9bdc06a7,0x1f83d9ab,0x5be0cd19};
    memcpy(ctx->s,iv,32); ctx->bits=0; ctx->idx=0;
}
static void sha256_step(sha256_ctx *ctx, const uint8_t *p){
    static const uint32_t K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(int i=0;i<16;i++){
        w[i] = ((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|((uint32_t)p[4*i+3]);
    }
    for(int i=16;i<64;i++){
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx->s[0], b=ctx->s[1], c=ctx->s[2], d=ctx->s[3];
    uint32_t e=ctx->s[4], f=ctx->s[5], g=ctx->s[6], h=ctx->s[7];
    for(int i=0;i<64;i++){
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d + t1;
        d=c; c=b; b=a; a=t1 + t2;
    }
    ctx->s[0]+=a; ctx->s[1]+=b; ctx->s[2]+=c; ctx->s[3]+=d;
    ctx->s[4]+=e; ctx->s[5]+=f; ctx->s[6]+=g; ctx->s[7]+=h;
}
static void sha256_update(sha256_ctx *ctx, const void *data, size_t len){
    const uint8_t *p=(const uint8_t*)data;
    ctx->bits += (uint64_t)len * 8;
    while(len){
        size_t n = 64 - ctx->idx; if(n>len) n=len;
        memcpy(ctx->buf + ctx->idx, p, n); ctx->idx += n; p += n; len -= n;
        if(ctx->idx==64){ sha256_step(ctx,ctx->buf); ctx->idx=0; }
    }
}
static void sha256_final(sha256_ctx *ctx, uint8_t out[32]){
    size_t i=ctx->idx;
    ctx->buf[i++]=0x80;
    if(i>56){ while(i<64) ctx->buf[i++]=0; sha256_step(ctx,ctx->buf); i=0; }
    while(i<56) ctx->buf[i++]=0;
    for(int j=7;j>=0;j--) ctx->buf[i++]=(ctx->bits>>(j*8)) & 0xff;
    sha256_step(ctx,ctx->buf);
    for(int k=0;k<8;k++){
        out[4*k  ]=(ctx->s[k]>>24)&0xff; out[4*k+1]=(ctx->s[k]>>16)&0xff;
        out[4*k+2]=(ctx->s[k]>>8 )&0xff; out[4*k+3]= ctx->s[k]     &0xff;
    }
}
static void dsha256(const void*data,size_t len,uint8_t out[32]){
    uint8_t t[32]; sha256_ctx c; sha256_init(&c); sha256_update(&c,data,len); sha256_final(&c,t);
    sha256_init(&c); sha256_update(&c,t,32); sha256_final(&c,out);
}

/* ============ hex & endianness utils ============ */
static int hexnib(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int hex2bin(const char*hex,uint8_t*out,size_t outcap){
    size_t n=strlen(hex); if(n%2) return -1; if(outcap<n/2) return -2;
    for(size_t i=0;i<n;i+=2){ int a=hexnib(hex[i]), b=hexnib(hex[i+1]); if(a<0||b<0) return -3; out[i/2]=(a<<4)|b; }
    return (int)(n/2);
}
static void rev32(uint8_t *p){ for(int i=0;i<16;i++){ uint8_t t=p[i]; p[i]=p[31-i]; p[31-i]=t; } }
static void u32le(uint8_t *p, uint32_t v){ p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }
static int be256_cmp(const uint8_t *a,const uint8_t *b){ for(int i=0;i<32;i++){ if(a[i]<b[i]) return -1; if(a[i]>b[i]) return 1; } return 0; }
static void target_from_nbits(const char *nbits_hex, uint8_t out[32]){
    uint8_t n[4]; hex2bin(nbits_hex,n,4);
    uint32_t exp=n[0], mant=(n[1]<<16)|(n[2]<<8)|n[3];
    memset(out,0,32);
    int idx = exp - 3; if(idx<0) idx=0; if(idx>29) idx=29;
    int pos = 32 - 3 - idx;
    out[pos  ] = (mant>>16)&0xff; out[pos+1] = (mant>>8)&0xff; out[pos+2] = mant&0xff;
}

/* ============ Stratum ultra-minimal ============ */
static int tcp_connect(const char*host,const char*port){
    struct addrinfo hints, *res, *rp; memset(&hints,0,sizeof hints);
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    int rc=getaddrinfo(host,port,&hints,&res); if(rc!=0){ warnx("getaddrinfo: %s", gai_strerror(rc)); return -1; }
    int s=-1;
    for(rp=res; rp; rp=rp->ai_next){
        s=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);
        if(s==-1) continue;
        if(connect(s,rp->ai_addr,rp->ai_addrlen)==0) break;
        close(s); s=-1;
    }
    freeaddrinfo(res);
    return s;
}
static int sendf(int s, const char *fmt, ...){
    char buf[1024]; va_list ap; va_start(ap,fmt); vsnprintf(buf,sizeof buf,fmt,ap); va_end(ap);
    size_t len=strlen(buf);
    ssize_t n=write(s,buf,len);
    return (n==(ssize_t)len)?0:-1;
}
static int readline(int s, char *out, size_t cap, int timeout_ms){
    fd_set rfds; struct timeval tv; FD_ZERO(&rfds); FD_SET(s,&rfds);
    tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
    int rv = select(s+1,&rfds,NULL,NULL,&tv);
    if(rv<=0) return rv; // 0 timeout, -1 err
    size_t i=0; char c;
    while(i+1<cap){
        int n=read(s,&c,1); if(n<=0) return n;
        if(c=='\n'){ out[i]=0; return (int)i; }
        out[i++]=c;
    }
    out[cap-1]=0; return (int)(cap-1);
}

/* JSON helper ultra-simple */
static int json_find_str(const char*json,const char*key,char*out,size_t cap){
    char pat[64]; snprintf(pat,sizeof pat,"\"%s\"",key);
    const char *p=strstr(json,pat); if(!p) return 0;
    p=strchr(p,':'); if(!p) return 0; p++;
    while(*p==' '||*p=='\"') { if(*p=='\"'){ p++; break; } p++; }
    const char *q=strchr(p,'\"'); if(!q) return 0;
    size_t n=(size_t)(q-p); if(n>=cap) n=cap-1; memcpy(out,p,n); out[n]=0; return 1;
}

/* mining.notify (très simplifié) */
struct job {
    char job_id[128], prevhash_hex[65], coinb1[512], coinb2[512];
    char merkle[16][65]; int merkle_cnt;
    char version_hex[9], nbits_hex[9], ntime_hex[9];
    int clean;
    char extranonce1[64]; int extranonce2_size;
    double diff;
};
static int parse_notify(const char*line, struct job *j){
    const char *p=line; int q=0; char tok[512]; int tlen=0;
    char items[12][512]; int ic=0; memset(items,0,sizeof items);
    while(*p && ic<12){
        if(*p=='\"'){ q=!q; if(!q){ tok[tlen]=0; strncpy(items[ic++], tok, sizeof(items[0])-1); tlen=0; } else tlen=0; p++; continue; }
        if(q){ if(tlen<(int)sizeof(tok)-1) tok[tlen++]=*p; }
        p++;
    }
    if(ic<6) return 0;
    strncpy(j->job_id, items[0], sizeof j->job_id-1);
    strncpy(j->prevhash_hex, items[1], sizeof j->prevhash_hex-1);
    strncpy(j->coinb1, items[2], sizeof j->coinb1-1);
    strncpy(j->coinb2, items[3], sizeof j->coinb2-1);

    j->merkle_cnt=0;
    const char *m=strstr(line,"["); const char *me=strstr(line,"]");
    if(m && me && me>m){
        const char *x=m;
        while((x=strchr(x,'\"')) && x<me && j->merkle_cnt<16){
            const char *y=strchr(x+1,'\"'); if(!y) break;
            int n=(int)(y-(x+1));
            if(n==64){ strncpy(j->merkle[j->merkle_cnt], x+1, 64); j->merkle[j->merkle_cnt][64]=0; j->merkle_cnt++; }
            x=y+1;
        }
    }
    char last8[3][9]={{0}}; int found=0; p=line;
    while((p=strchr(p,'\"'))){ const char *q2=strchr(p+1,'\"'); if(!q2) break;
        int n=(int)(q2-(p+1)); if(n==8 && found<3){ strncpy(last8[found], p+1, 8); last8[found][8]=0; found++; }
        p=q2+1;
    }
    if(found>=3){ strncpy(j->version_hex,last8[0],8); strncpy(j->nbits_hex,last8[1],8); strncpy(j->ntime_hex,last8[2],8); }
    return 1;
}
static void merkle_root(const uint8_t *coinbase_hash_be, struct job *j, uint8_t out_be[32]){
    uint8_t cur[32]; memcpy(cur, coinbase_hash_be, 32);
    for(int i=0;i<j->merkle_cnt;i++){
        uint8_t b[32]; hex2bin(j->merkle[i], b, 32);
        uint8_t a_le[32], b_le[32]; memcpy(a_le,cur,32); rev32(a_le); memcpy(b_le,b,32); rev32(b_le);
        uint8_t cat[64]; memcpy(cat,a_le,32); memcpy(cat+32,b_le,32);
        uint8_t h[32]; dsha256(cat,64,h); memcpy(cur,h,32);
    }
    memcpy(out_be, cur, 32);
}

/* ============ Stats ============ */
static double now_sec(void){ struct timeval tv; gettimeofday(&tv,NULL); return tv.tv_sec + tv.tv_usec/1e6; }

/* ============ Main ============ */
int main(int argc, char **argv){
    if(argc<5){
        fprintf(stderr,"Usage: %s <host> <port> <user.worker> <password>\n", argv[0]);
        return 1;
    }
    const char *host=argv[1], *port=argv[2], *user=argv[3], *pass=argv[4];

    struct job J; memset(&J,0,sizeof J);
    strcpy(J.extranonce1,""); J.extranonce2_size=4; J.diff=1.0;

    uint32_t extranonce2_counter=1;
    char line[4096];
    double last_print = now_sec();
    unsigned long long hashes_since = 0ULL, shares_ok=0ULL, shares_err=0ULL;

    int backoff = 1; // seconds, grows to 10
reconnect:
    memset(&J,0,sizeof J); strcpy(J.extranonce1,""); J.extranonce2_size=4; J.diff=1.0;
    int s = tcp_connect(host,port);
    if(s<0){ warnx("[!] connect failed; retry in %ds", backoff); sleep(backoff); if(backoff<10) backoff++; goto reconnect; }

    if(sendf(s, "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"armv5-toy/0.3\"]}\n")<0){ close(s); sleep(backoff); if(backoff<10) backoff++; goto reconnect; }
    if(sendf(s, "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n", user, pass)<0){ close(s); sleep(backoff); if(backoff<10) backoff++; goto reconnect; }
    warnx("[i] connected, subscribed/authorized");
    backoff = 1; // reset on success

    double loop_start = now_sec();

    while(1){
        // read lines with a small timeout to allow mining loop time slicing
        int r = readline(s,line,sizeof line, 200);
        if(r==0){ // timeout: do mining step if we have a job
            if(J.job_id[0]){
                // Build once per iteration range
                char ex2hex[16]; snprintf(ex2hex,sizeof ex2hex,"%08x", extranonce2_counter++);
                char coinbase_hex[1536]={0};
                strncat(coinbase_hex,J.coinb1,sizeof coinbase_hex - strlen(coinbase_hex) - 1);
                if(J.extranonce1[0]) strncat(coinbase_hex,J.extranonce1,sizeof coinbase_hex - strlen(coinbase_hex) - 1);
                strncat(coinbase_hex,ex2hex,sizeof coinbase_hex - strlen(coinbase_hex) - 1);
                strncat(coinbase_hex,J.coinb2,sizeof coinbase_hex - strlen(coinbase_hex) - 1);

                uint8_t coinbase_bin[768]; int cb_len = hex2bin(coinbase_hex, coinbase_bin, sizeof coinbase_bin);
                if(cb_len>=0){
                    uint8_t cb_hash[32]; dsha256(coinbase_bin, (size_t)cb_len, cb_hash);
                    uint8_t mr_be[32]; merkle_root(cb_hash,&J,mr_be);

                    uint8_t hdr[80];
                    uint8_t version_be[4]; hex2bin(J.version_hex,version_be,4);
                    u32le(hdr+0, ((uint32_t)version_be[0]<<24)|((uint32_t)version_be[1]<<16)|((uint32_t)version_be[2]<<8)|version_be[3]);

                    uint8_t prev_be[32]; hex2bin(J.prevhash_hex,prev_be,32);
                    memcpy(hdr+4, prev_be, 32); rev32(hdr+4);

                    uint8_t mr_le[32]; memcpy(mr_le, mr_be, 32); rev32(mr_le);
                    memcpy(hdr+36, mr_le, 32);

                    uint8_t ntime_be[4]; hex2bin(J.ntime_hex,ntime_be,4);
                    hdr[68]=ntime_be[3]; hdr[69]=ntime_be[2]; hdr[70]=ntime_be[1]; hdr[71]=ntime_be[0];

                    uint8_t nbits_be[4]; hex2bin(J.nbits_hex,nbits_be,4);
                    hdr[72]=nbits_be[3]; hdr[73]=nbits_be[2]; hdr[74]=nbits_be[1]; hdr[75]=nbits_be[0];

                    uint8_t target_be[32]; target_from_nbits(J.nbits_hex, target_be);

                    uint32_t base_nonce = (uint32_t)time(NULL);
                    for(uint32_t i=0;i<2000;i++){ // petite tranche pour rester réactif I/O
                        uint32_t nonce = base_nonce + i;
                        u32le(hdr+76, nonce);
                        uint8_t h[32]; dsha256(hdr,80,h);
                        hashes_since++;

                        if(be256_cmp(h, target_be) <= 0){
                            char nonce_hex[9]; snprintf(nonce_hex,sizeof nonce_hex,"%08x", nonce);
                            char params[512];
                            snprintf(params,sizeof params,"[\"%s\",\"%s\",\"%08x\",\"%s\",\"%s\"]",
                                     user, J.job_id, (unsigned)strtoul(ex2hex,NULL,16), J.ntime_hex, nonce_hex);
                            if(sendf(s, "{\"id\":4,\"method\":\"mining.submit\",\"params\":%s}\n", params)<0){
                                warnx("[!] submit send failed; reconnect…");
                                close(s); sleep(backoff); if(backoff<10) backoff++; goto reconnect;
                            }
                            warnx("[+] SHARE nonce=%s ex2=%s", nonce_hex, ex2hex);
                            break; // reprend un nouvel ex2 au tour suivant
                        }
                    }
                }
            }
            // stats toutes les 10s
            double t = now_sec();
            if(t - last_print >= 10.0){
                double dt = t - last_print;
                double hps = hashes_since / (dt>0?dt:1);
                warnx("[stats] hashrate ~ %.2f H/s | shares ok=%llu err=%llu", hps, shares_ok, shares_err);
                hashes_since = 0ULL; last_print = t;
            }
            continue;
        } else if(r<0){
            warnx("[!] disconnected (read err/timeout); reconnect in %ds", backoff);
            close(s); sleep(backoff); if(backoff<10) backoff++; goto reconnect;
        }

        // got a line
        // printf("<< %s\n", line);

        if(strstr(line,"mining.set_difficulty")){
            const char *p=strchr(line,'['); double d=1.0; if(p){ d=atof(p+1); if(d<=0)d=1.0; }
            J.diff=d; // informatif
        }
        else if(strstr(line,"mining.notify")){
            if(!parse_notify(line,&J)){ warnx("[!] notify parse failed"); continue; }
            // reset nonce window
        }
        else if(strstr(line,"mining.subscribe") && strstr(line,"result")){
            // essayer d'extraire extranonce1 si présent
            char res[1024]; if(json_find_str(line,"result",res,sizeof res)){
                // JSON naïf: pas fiable. On laisse extranonce1 vide (ça marche sur plein de pools).
            }
        }
        else if(strstr(line,"mining.submit") && strstr(line,"result")){
            // réponse partage soumis
            if(strstr(line,"\"result\": true")) { shares_ok++; }
            else if(strstr(line,"\"result\":false")) { shares_err++; }
        }
        else if(strstr(line,"error") && strstr(line,"mining.submit")){
            shares_err++;
        }

        // stats toutes les 10s (même si I/O actif)
        double t = now_sec();
        if(t - last_print >= 10.0){
            double dt = t - last_print;
            double hps = hashes_since / (dt>0?dt:1);
            warnx("[stats] hashrate ~ %.2f H/s | shares ok=%llu err=%llu", hps, shares_ok, shares_err);
            hashes_since = 0ULL; last_print = t;
        }
    }
    return 0;
}
