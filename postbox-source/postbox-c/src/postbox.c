#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>

#define STORE "mailbox"
#define LIMIT 65536
/* Local message envelope. Public-key operations protect message keys,
   establish session material, and authenticate stored correspondence. */
typedef struct {
    unsigned char magic[8], nonce[12], tag[16];
    uint32_t length, wrapped_length, author_length, receipt_length;
    char recipient[160], subject[200];
    unsigned char wrapped[512], author[128], receipt[128];
    unsigned char ciphertext[LIMIT];
} Envelope;

static void fail(const char *message) {
    fprintf(stderr, "Postbox: %s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}
static void check(int ok, const char *message) { if (ok <= 0) fail(message); }
static void path(char *out, size_t n, const char *name) {
    if (snprintf(out, n, "%s/%s", STORE, name) >= (int)n) fail("Path too long.");
}
static EVP_PKEY *generate(const char *kind, const char *group) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, kind, NULL);
    EVP_PKEY *key = NULL, *params = NULL;
    if (!ctx) fail("Cannot prepare identity.");
    if (!strcmp(kind, "DSA")) {
        check(EVP_PKEY_paramgen_init(ctx), "Cannot prepare signing parameters.");
        check(EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048), "Cannot set signing parameters.");
        check(EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, 256), "Cannot set subgroup.");
        check(EVP_PKEY_paramgen(ctx, &params), "Cannot generate signing parameters.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(params, NULL);
        if (!ctx) fail("Cannot prepare signing identity.");
    }
    check(EVP_PKEY_keygen_init(ctx), "Cannot prepare key generation.");
    if (group) check(EVP_PKEY_CTX_set_group_name(ctx, group), "Cannot set identity group.");
    if (!strcmp(kind, "RSA")) check(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072), "Cannot set identity size.");
    check(EVP_PKEY_keygen(ctx, &key), "Cannot create identity.");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(params);
    return key;
}
static void save_key(const char *name, EVP_PKEY *key) {
    char filename[256]; path(filename, sizeof filename, name);
    FILE *file = fopen(filename, "wx");
    if (!file) fail("Cannot create identity file; existing identities are never overwritten.");
    check(PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL), "Cannot save identity.");
    check(fclose(file) == 0, "Cannot finish identity file.");
}
static EVP_PKEY *load_key(const char *name) {
    char filename[256]; path(filename, sizeof filename, name);
    FILE *file = fopen(filename, "r");
    if (!file) fail("Workspace not initialized. Run postbox init first.");
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) fail("Cannot read identity.");
    return key;
}
static void init(void) {
    struct stat st;
    if (!stat(STORE, &st)) fail("A workspace already exists; it has not been changed.");
    check(mkdir(STORE, 0700) == 0, "Cannot create workspace.");
    const char *names[] = {"recipient.pem", "author.pem", "receipt.pem", "session-local.pem", "session-peer.pem", "relay-local.pem", "relay-peer.pem"};
    const char *kinds[] = {"RSA", "EC", "DSA", "EC", "EC", "DH", "DH"};
    const char *groups[] = {NULL, "prime256v1", NULL, "prime256v1", "prime256v1", "ffdhe2048", "ffdhe2048"};
    for (size_t i = 0; i < 7; i++) {
        EVP_PKEY *key = generate(kinds[i], groups[i]);
        save_key(names[i], key);
        EVP_PKEY_free(key);
    }
    puts("Workspace ready. You can now compose a message.");
}
/* ECDH and finite-field DH are distinct session exchanges. Both parties
   derive independently; matching secrets are required before key derivation. */
static void exchange(const char *local_name, const char *peer_name, unsigned char digest[32]) {
    EVP_PKEY *local = load_key(local_name), *peer = load_key(peer_name);
    unsigned char secrets[2][512]; size_t lengths[2] = {512, 512};
    for (int side = 0; side < 2; side++) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(side ? peer : local, NULL);
        if (!ctx) fail("Cannot prepare session.");
        check(EVP_PKEY_derive_init(ctx), "Cannot initialize session.");
        check(EVP_PKEY_derive_set_peer(ctx, side ? local : peer), "Cannot accept session peer.");
        check(EVP_PKEY_derive(ctx, secrets[side], &lengths[side]), "Cannot establish session.");
        EVP_PKEY_CTX_free(ctx);
    }
    if (lengths[0] != lengths[1] || CRYPTO_memcmp(secrets[0], secrets[1], lengths[0])) fail("Session confirmation failed.");
    unsigned int n;
    check(EVP_Digest(secrets[0], lengths[0], digest, &n, EVP_sha256(), NULL), "Cannot derive session material.");
    OPENSSL_cleanse(secrets, sizeof secrets);
    EVP_PKEY_free(local); EVP_PKEY_free(peer);
}
static void wrap_key(int encrypt, unsigned char key[32], Envelope *mail) {
    EVP_PKEY *recipient = load_key("recipient.pem");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(recipient, NULL);
    if (!ctx) fail("Cannot prepare message key.");
    check(encrypt ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx), "Cannot prepare message key.");
    /* RSA-OAEP wraps the per-message AES key. */
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "Cannot set key wrapping.");
    check(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()), "Cannot set key wrapping digest.");
    check(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()), "Cannot set wrapping mask.");
    size_t length = encrypt ? sizeof mail->wrapped : 512;
    unsigned char plain[512];
    if (encrypt) {
        check(EVP_PKEY_encrypt(ctx, mail->wrapped, &length, key, 32), "Cannot seal message key.");
        mail->wrapped_length = (uint32_t)length;
    } else {
        check(EVP_PKEY_decrypt(ctx, plain, &length, mail->wrapped, mail->wrapped_length), "Cannot open message key.");
        if (length != 32) fail("Invalid message key.");
        memcpy(key, plain, 32); OPENSSL_cleanse(plain, sizeof plain);
    }
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(recipient);
}
/* Each signature covers all routing fields, wrapped key, authentication tag,
   and ciphertext. Signatures themselves are excluded from the transcript. */
static void transcript(EVP_MD_CTX *ctx, const Envelope *mail, int verify) {
#define FEED(ptr, len) check(verify ? EVP_DigestVerifyUpdate(ctx, ptr, len) : EVP_DigestSignUpdate(ctx, ptr, len), "Cannot authenticate message.")
    FEED(mail->magic, 8); FEED(mail->nonce, 12); FEED(mail->tag, 16);
    FEED(&mail->length, sizeof mail->length); FEED(&mail->wrapped_length, sizeof mail->wrapped_length);
    FEED(mail->recipient, sizeof mail->recipient); FEED(mail->subject, sizeof mail->subject);
    FEED(mail->wrapped, mail->wrapped_length); FEED(mail->ciphertext, mail->length);
#undef FEED
}
static void signature(Envelope *mail, int receipt, int verify) {
    /* ECDSA authenticates authorship; DSA authenticates the local receipt. */
    EVP_PKEY *key = load_key(receipt ? "receipt.pem" : "author.pem");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) fail("Cannot prepare message authentication.");
    unsigned char *bytes = receipt ? mail->receipt : mail->author;
    uint32_t *size = receipt ? &mail->receipt_length : &mail->author_length;
    check(verify ? EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) : EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key), "Cannot initialize message authentication.");
    transcript(ctx, mail, verify);
    if (verify) check(EVP_DigestVerifyFinal(ctx, bytes, *size), "Message authentication failed.");
    else {
        size_t n = 128;
        check(EVP_DigestSignFinal(ctx, bytes, &n), "Cannot sign message.");
        *size = (uint32_t)n;
    }
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
}
static void crypt_body(Envelope *mail, unsigned char key[32], unsigned char *text, int encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0;
    if (!ctx) fail("Cannot prepare message.");
    if (encrypt) {
        check(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, mail->nonce), "Cannot prepare envelope.");
        check(EVP_EncryptUpdate(ctx, mail->ciphertext, &n, text, (int)mail->length), "Cannot seal message.");
        check(EVP_EncryptFinal_ex(ctx, mail->ciphertext + n, &tail), "Cannot finish envelope.");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mail->tag), "Cannot seal envelope.");
    } else {
        check(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, mail->nonce), "Cannot prepare envelope.");
        check(EVP_DecryptUpdate(ctx, text, &n, mail->ciphertext, (int)mail->length), "Cannot open envelope.");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, mail->tag), "Cannot check envelope.");
        check(EVP_DecryptFinal_ex(ctx, text + n, &tail), "Message integrity check failed.");
        text[n + tail] = '\0';
    }
    EVP_CIPHER_CTX_free(ctx);
}
static void send_mail(const char *recipient, const char *subject, const char *text) {
    Envelope *mail = calloc(1, sizeof *mail);
    if (!mail) fail("Not enough memory.");
    size_t length = strlen(text);
    if (!length || length >= LIMIT || strlen(recipient) >= sizeof mail->recipient || strlen(subject) >= sizeof mail->subject) fail("Message is empty or too long.");
    memcpy(mail->magic, "POSTBOX1", 8); mail->length = (uint32_t)length;
    strcpy(mail->recipient, recipient); strcpy(mail->subject, subject);
    unsigned char material[96], key[32]; unsigned int n;
    check(RAND_bytes(material, 32), "Cannot create message key.");
    exchange("session-local.pem", "session-peer.pem", material + 32);
    exchange("relay-local.pem", "relay-peer.pem", material + 64);
    check(EVP_Digest(material, sizeof material, key, &n, EVP_sha256(), NULL), "Cannot derive message key.");
    check(RAND_bytes(mail->nonce, 12), "Cannot create envelope.");
    crypt_body(mail, key, (unsigned char *)text, 1); wrap_key(1, key, mail);
    signature(mail, 0, 0); signature(mail, 1, 0);
    char filename[256];
    snprintf(filename, sizeof filename, STORE "/%ld-%ld.pbx", (long)time(NULL), (long)getpid());
    FILE *file = fopen(filename, "wbx");
    if (!file) fail("Cannot store message.");
    check(fwrite(mail, sizeof *mail, 1, file) == 1, "Cannot write message.");
    check(fclose(file) == 0, "Cannot finish message.");
    printf("Message saved for %s.\nReference: %s\n", recipient, strrchr(filename, '/') + 1);
    OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(material, sizeof material); free(mail);
}
static Envelope *load_mail(const char *name) {
    if (strchr(name, '/') || strstr(name, "..")) fail("Invalid message reference.");
    char filename[256]; path(filename, sizeof filename, name);
    FILE *file = fopen(filename, "rb");
    if (!file) fail("Message not found.");
    Envelope *mail = calloc(1, sizeof *mail);
    if (!mail) fail("Not enough memory.");
    if (fread(mail, sizeof *mail, 1, file) != 1 || fgetc(file) != EOF) fail("Invalid message envelope.");
    fclose(file);
    if (memcmp(mail->magic, "POSTBOX1", 8) || mail->length >= LIMIT || !mail->wrapped_length || mail->wrapped_length > 512 || !mail->author_length || mail->author_length > 128 || !mail->receipt_length || mail->receipt_length > 128 || !memchr(mail->recipient, 0, 160) || !memchr(mail->subject, 0, 200)) fail("Invalid message envelope.");
    signature(mail, 0, 1); signature(mail, 1, 1);
    return mail;
}
static void read_mail(const char *name) {
    Envelope *mail = load_mail(name);
    unsigned char key[32], text[LIMIT + 16];
    wrap_key(0, key, mail); crypt_body(mail, key, text, 0);
    printf("To: %s\nSubject: %s\n\n%s\n", mail->recipient, mail->subject, text);
    OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(text, sizeof text); free(mail);
}
static void list_mail(void) {
    DIR *dir = opendir(STORE); if (!dir) fail("Workspace not initialized.");
    struct dirent *entry; int count = 0;
    while ((entry = readdir(dir))) {
        size_t n = strlen(entry->d_name);
        if (n < 4 || strcmp(entry->d_name + n - 4, ".pbx")) continue;
        Envelope *mail = load_mail(entry->d_name);
        printf("%s  |  %s  |  %s\n", entry->d_name, mail->recipient, mail->subject);
        free(mail); count++;
    }
    closedir(dir); if (!count) puts("No conversations yet.");
}
int main(int argc, char **argv) {
    umask(0077);
    if (argc == 2 && !strcmp(argv[1], "init")) init();
    else if (argc == 2 && !strcmp(argv[1], "list")) list_mail();
    else if (argc == 3 && !strcmp(argv[1], "read")) read_mail(argv[2]);
    else if (argc == 5 && !strcmp(argv[1], "send")) send_mail(argv[2], argv[3], argv[4]);
    else { puts("Postbox — personal correspondence\n\n  postbox init\n  postbox send <recipient> <subject> <message>\n  postbox list\n  postbox read <reference>\n\nMessages are stored locally. No email is delivered."); return argc == 1 ? 0 : 1; }
    return 0;
}
