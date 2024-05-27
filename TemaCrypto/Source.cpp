#pragma warning(disable:4996)
#include <iostream>
#include <openssl/ecdh.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <cstring>
#include<openssl/applink.c>
#include<openssl/asn1.h>
#include<openssl/asn1t.h>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

typedef struct Message {
    ASN1_INTEGER* ID;
    ASN1_PRINTABLESTRING* Text;
    ASN1_INTEGER* TextLen;
}Message;
DEFINE_STACK_OF(Message)
ASN1_SEQUENCE(Message) = {
    ASN1_SIMPLE(Message,ID,ASN1_INTEGER),
    ASN1_SIMPLE(Message,Text,ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Message,TextLen,ASN1_INTEGER)
}ASN1_SEQUENCE_END(Message);
DECLARE_ASN1_FUNCTIONS(Message);
IMPLEMENT_ASN1_FUNCTIONS(Message);


typedef struct Conversation {
    STACK_OF(Message)* Messages;
}Conversation;
ASN1_SEQUENCE(Conversation) = {
    ASN1_SIMPLE(Conversation,Messages,Message),
}ASN1_SEQUENCE_END(Conversation);
DECLARE_ASN1_FUNCTIONS(Conversation);
IMPLEMENT_ASN1_FUNCTIONS(Conversation);


int aes_encrypt(unsigned char* plaintext, int plainLen,const unsigned char* key, const unsigned char* iv,unsigned char** ciphertext, int& cipherLen)
{
    EVP_CIPHER_CTX* ctx;
    if (key == NULL || iv == NULL)
    {
        printf("Nu s-a efectuat handshake-ul!!!");
        return -1;
    }
    const EVP_CIPHER* cipher = EVP_aes_256_cfb();
    (*ciphertext) = new unsigned char[plainLen+AES_BLOCK_SIZE];
    int lenUpdate, lenFinal;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, cipher, key, iv);
    EVP_EncryptUpdate(ctx, *ciphertext, &lenUpdate, plaintext, plainLen);
    EVP_EncryptFinal(ctx, *ciphertext + lenUpdate, &lenFinal);
    cipherLen = lenUpdate + lenFinal;
    EVP_CIPHER_CTX_free(ctx);
    (*ciphertext)[cipherLen]='\0';
    return 0;
}

Message* generate_message( unsigned char* text, int textLen, int& messageID)
{
    
    Message* message = Message_new();
    message->Text = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(message->Text, text, textLen);
    ASN1_INTEGER_set(message->ID, messageID);
    ASN1_INTEGER_set(message->TextLen, textLen);
    messageID++;
    return message;
}


void generate_ecdhkeysCurve25519AndCertificates(const char* filenamepriv, const char* filenamepub, int SerialNumber, const char* CommonName, const char* CertificateFile,const char* user) {
    FILE* f1 = fopen(filenamepriv, "w");
    FILE* f2 = fopen(filenamepub, "w");
    EVP_PKEY* pkey = NULL;
    size_t lenCurve25519 = 32;
    unsigned char pub[32];
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_get_raw_public_key(pkey, pub, &lenCurve25519);
    EVP_PKEY* pubKEY = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, lenCurve25519);

    PEM_write_PrivateKey(f1, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(f2, pubKEY);


    char* filename = (char*)malloc(100);
    strcpy(filename, user);
    strcat(filename, "RAW");
    strcat(filename, ".txt");
    FILE* f3 = fopen(filename, "w");
    fwrite(pub, 1,32 , f3);

    fclose(f1);
    fclose(f2);
    fclose(f3);

    X509* cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), SerialNumber);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* certName = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(certName, "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(certName, "O", MBSTRING_ASC, (unsigned char*)"MTA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(certName, "CN", MBSTRING_ASC, (unsigned char*)CommonName, -1, -1, 0);
    X509_set_issuer_name(cert, certName);

    EVP_PKEY* signing_key = EVP_PKEY_new();
    EVP_PKEY_CTX* sctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(sctx);
    EVP_PKEY_keygen(sctx, &signing_key);
    EVP_PKEY_CTX_free(sctx);

    if (!X509_sign(cert, signing_key, NULL)) {
        std::cerr << "Failed to sign certificate" << std::endl;
    }

    BIO* file = BIO_new_file(CertificateFile, "wb");
    if (file != nullptr) {
        PEM_write_bio_X509(file, cert);
        BIO_free(file);
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pubKEY);
    EVP_PKEY_free(signing_key);
    X509_free(cert);
}

void GenerareCheiEfemere() {
    generate_ecdhkeysCurve25519AndCertificates("EntitateAlice_PrivateKeyX.pem", "EntitateAlice_PublicKeyX.pem", 1, "Certificat1", "Certificat1.crt","Alice");
    generate_ecdhkeysCurve25519AndCertificates("EntitateBob_PrivateKeyX.pem", "EntitateBob_PublicKeyX.pem", 2, "Certificat2", "Certificat2.crt","Bob");
}


void generateED25519keysInFiles(const char* filePrivKey, const char* filePubKey) {
    EVP_PKEY* pkey = NULL;
    size_t lenCurve25519;
    unsigned char* pub = new unsigned char[32];
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);


    EVP_PKEY_get_raw_public_key(pkey, pub, &lenCurve25519);
    EVP_PKEY* pubKEY = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, lenCurve25519); 
    FILE* f1 = fopen(filePrivKey, "w");
    FILE* f2 = fopen(filePubKey, "w");
    PEM_write_PrivateKey(f1, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(f2, pubKEY); 
    
    fclose(f1);
    fclose(f2);
}




unsigned char* generateED25519Signature(const char*filenamePrivKey, const unsigned char* message, size_t lenMessage, size_t& sigLen) {

    FILE* f = fopen(filenamePrivKey, "r");
    EVP_PKEY* privateKey=EVP_PKEY_new();
    PEM_read_PrivateKey(f, &privateKey, NULL, 0);


    unsigned char* signature;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        signature = nullptr;
        sigLen = 0;
        return NULL;
    }

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, privateKey) != 1) {
        EVP_MD_CTX_free(mdctx);
        signature = nullptr;
        sigLen = 0;
        return NULL;
    }

    if (EVP_DigestSign(mdctx, nullptr, &sigLen, message, lenMessage) != 1) {
        EVP_MD_CTX_free(mdctx);
        signature = nullptr;
       sigLen = 0;
        return NULL;
    }

    signature = new unsigned char[sigLen];
    if (signature == nullptr) {
        EVP_MD_CTX_free(mdctx);
        sigLen = 0;
        return NULL;
    }

    if (EVP_DigestSign(mdctx, signature, &sigLen, message, lenMessage) != 1) {
        delete[] signature;
        signature = nullptr;
        sigLen = 0;
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);
    ASN1_STRING* derSignature = ASN1_STRING_new();
    ASN1_STRING_set0(derSignature, signature,sigLen);

    unsigned char* derData = NULL;
    int derLen = i2d_ASN1_OCTET_STRING(derSignature, &derData);

    if (derLen < 0) {
        std::cerr << "Error encoding signature as DER." << std::endl;
        OPENSSL_free(derData);
        ASN1_STRING_free(derSignature);
        return nullptr;
    }

    sigLen = derLen;

    return derData;

}




void ECDHExchange(const char* filenamePrivA, const char* filenamePubB, unsigned char** skey, int& skeyLen,const char*signerFileName,const char*user) {
    FILE* fp1 = fopen(filenamePrivA, "r");
    FILE* fp2 = fopen(filenamePubB, "r");
    if (!fp1 || !fp2) {
        std::cerr << "Error opening files." << std::endl;
        return;
    }
   
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp1, NULL, NULL, NULL);
    EVP_PKEY* peerkey = PEM_read_PUBKEY(fp2, NULL, NULL, NULL);
    fclose(fp1);
    fclose(fp2);
    char* filename = (char*)malloc(100);
    strcpy(filename, user);
    strcat(filename, "RAW");
    strcat(filename, ".txt");
    FILE* f = fopen(filename, "r");
    char* content = (char*)malloc(1000);
    int readBytes= fread(content,1,1000,f);
    content[readBytes] = '\0';
    fclose(f);
    size_t signatureLen;
    char*signature=(char*)generateED25519Signature(signerFileName, (const unsigned char*)content, 32, signatureLen);
     signature[signatureLen] = '\0';
    char filenameConversation[100];
    strcpy(filenameConversation, "Entitate_");
    strcat(filenameConversation, user);
    strcat(filenameConversation, ".dat");

    char* toWrite = (char*)malloc(1000);
    sprintf(toWrite, "%s %s%s", "HANDSHAKE", content, signature);

    f=fopen(filenameConversation, "a");
    toWrite[strlen(toWrite)] = '\0';
    fwrite(toWrite, 1, strlen(toWrite), f);
    fwrite("\n", 1, 1, f);
    fclose(f);
    

    if (!pkey || !peerkey) {
        std::cerr << "Error reading keys." << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "Error creating context." << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "Error initializing derivation." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        std::cerr << "Error setting peer key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    size_t skeylenLocal;
    if (EVP_PKEY_derive(ctx, NULL, &skeylenLocal) <= 0) {
        std::cerr << "Error deriving key length." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    *skey = (unsigned char*)OPENSSL_malloc(skeylenLocal);
    if (!*skey) {
        std::cerr << "Memory allocation error." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    if (EVP_PKEY_derive(ctx, *skey, &skeylenLocal) <= 0) {
        std::cerr << "Error deriving shared key." << std::endl;
        OPENSSL_free(*skey);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return;
    }

    skeyLen = (int)skeylenLocal;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    printf("Schimbul de chei a avut loc cu succes!");
}

bool shared_key_check(unsigned char* exchangedKey1, unsigned char* exchangedKey2, int length1, int length2) {
    if (length1 == length2) {
        if (memcmp(exchangedKey1, exchangedKey2, length1) == 0)
            return true;
    }
    return false;
}




unsigned char* PBKDF2( unsigned char* secretKey, int lengthkey,unsigned char** cryptkey,unsigned char** IV) {

    unsigned char salt[100];
    strcpy((char*)salt , "BanicaAlexandru");
    for (int i = strlen((char*)salt) - 1; i < 100; i++)
        salt[i] = 0x55;
    unsigned char* out = new unsigned char[48];
    PKCS5_PBKDF2_HMAC((char*)secretKey, lengthkey, salt, 100, 1024, EVP_sha384(), 48, out);
    if (!*cryptkey)
    {
        *cryptkey = (unsigned char*)malloc(32);
    }
    if (!*IV)
    {
        *IV = (unsigned char*)malloc(16);
    }
    memcpy(*cryptkey, out, 32);
    (*cryptkey)[32] = '\0';
    memcpy(*IV, out + 32, 16);
    (*IV)[16] = '\0';
    return out;
}


void Send_Message(int& messageID,unsigned char* key,unsigned char* IV,Conversation**conversation)
{
    printf("Introduceti mesajul pe care doriti sa-l trimiteti:\n");
    char message[1000];
    scanf("%s", message);
    unsigned char* ciphertext;
    int cipherLen;
    if (aes_encrypt((unsigned char*)message, strlen(message), key, IV, &ciphertext, cipherLen) < 0)
        return;
    sk_Message_push((*conversation)->Messages, generate_message(ciphertext,cipherLen,messageID));
}

void journalize_Conversation(Conversation* conversation, const char* user) {
    char filename[100];
    if (strcmp(user, "Alice") == 0) {
        strcpy(filename, "Entitate_Alice.dat");
    }
    else if (strcmp(user, "Bob") == 0) {
        strcpy(filename, "Entitate_Bob.dat");
    }
    else {
        printf("Invalid user specified\n");
        return;
    }

    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        printf("Could not open file %s for writing\n", filename);
        return;
    }

    for (int i = 0; i < sk_Message_num(conversation->Messages); i++) {
        Message* msg = sk_Message_value(conversation->Messages, i);
        if (msg != NULL) {
            ASN1_INTEGER* id = msg->ID;
            ASN1_PRINTABLESTRING* text = msg->Text;

            BIGNUM* bn = ASN1_INTEGER_to_BN(id, NULL);
            char* id_str = BN_bn2dec(bn);
            char* text_str = (char*)ASN1_STRING_get0_data(text);

            fprintf(file, "ID: %s, Text: %s\n", id_str, text_str);

            OPENSSL_free(id_str);
            BN_free(bn);
        }
    }

    fclose(file);

    while (sk_Message_num(conversation->Messages) > 0) {
        Message* msg = sk_Message_pop(conversation->Messages);
        Message_free(msg);
    }
}



void display_menu(unsigned char**cryptkey,unsigned char**IV,int messageID,Conversation**conversationAlice,Conversation**conversationBob)
{
    printf("\nIntroduceti user-ul(Alice/Bob):\n");
    char* user = (char*)malloc(100);
    scanf("%s", user);
    printf("Introduceti o optiune:\n");
    printf("1)Regenerare de chei de criptare\n");
    printf("2)Handshake\n");
    printf("3)Trimite mesaj(INAINTE DE A EFECTUA ACEASTA OPERATIUNE, TREBUIE FACUT HANDSHAKE!!!)\n");
    printf("4)Jurnalizare conversatie\n");
    printf("5)Verficare chei HANDSHAKE\n");
    printf("6)Iesire\n");
    int option;
    scanf("%d", &option);
    if (option == 1)
    {
        GenerareCheiEfemere();
    }
    else if (option == 2) {
        int skeyLen;
        unsigned char* skey;
        if (strcmp(user, "Alice") == 0)
        {
            
            ECDHExchange("EntitateAlice_PrivateKeyX.pem", "EntitateBob_PublicKeyX.pem",&skey,skeyLen,"PrivKeyAlice.pem", "Alice");
        }
        else
        {
            ECDHExchange("EntitateBob_PrivateKeyX.pem", "EntitateAlice_PublicKeyX.pem", &skey, skeyLen, "PrivKeyBob.pem", "Bob");
        }

        PBKDF2(skey, skeyLen,cryptkey,IV);

    }

    else if (option == 3)
    {
        if(strcmp(user,"Alice")==0)
            Send_Message(messageID,*cryptkey,*IV,conversationAlice);
        else
            Send_Message(messageID, *cryptkey, *IV, conversationBob);

    }
    else if (option == 4)
    {
        if (strcmp(user, "Alice") == 0) {
            journalize_Conversation(*conversationAlice, "Alice");
        }
        else {
            journalize_Conversation(*conversationBob, "Bob");
        }
    }

    else if (option == 5)
    {
        unsigned char* skey1;
        unsigned char*skey2;
        int skeyLen1, skeyLen2;
        ECDHExchange("EntitateAlice_PrivateKeyX.pem", "EntitateBob_PublicKeyX.pem", &skey1, skeyLen1, "PrivKeyAlice.pem", "Alice");
        ECDHExchange("EntitateBob_PrivateKeyX.pem", "EntitateAlice_PublicKeyX.pem", &skey2, skeyLen2, "PrivKeyBob.pem", "Bob");
        if (shared_key_check(skey1, skey2, skeyLen1, skeyLen2))
        {
            printf("Cheile sunt identice\n");
        }
        else
        {
            printf("Cheile nu sunt la fel\n");
        }

    }
    else if (option == 6)
    {
        exit(0);
    }
}

int main() {
   
    GenerareCheiEfemere();
    generateED25519keysInFiles("PrivKeyAlice.pem", "PubKeyAlice.pem");
    generateED25519keysInFiles("PrivKeyBob.pem", "PubKeyBob.pem");
    unsigned char* cryptkey = NULL;
    unsigned char* IV = NULL;
    int messageID = 1;
    Conversation* conversationAlice = Conversation_new();
    Conversation* conversationBob = Conversation_new();
    conversationAlice->Messages = sk_Message_new_null();
    conversationBob->Messages = sk_Message_new_null();
    while (true)
    {
        display_menu(&cryptkey,&IV,messageID,&conversationAlice,&conversationBob);
    }
    return 0;
}
