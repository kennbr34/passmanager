/* prototypes.c - function prototypes */

/* Copyright 2020 Kenneth Brown */

/* Licensed under the Apache License, Version 2.0 (the "License"); */
/* you may not use this file except in compliance with the License. */
/* You may obtain a copy of the License at */

/*     http://www.apache.org/licenses/LICENSE-2.0 */

/* Unless required by applicable law or agreed to in writing, software */
/* distributed under the License is distributed on an "AS IS" BASIS, */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and */
/* limitations under the License. */

/*

  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/

void disablePtrace();
void lockMemory();
void parseOptions(int argc, char *argv[], struct cryptoVar *cryptoStructPtr, struct dbVar *dbStructPtr, struct textBuf *textBuffersStruct, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int openDatabase(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int writeDatabase(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int backupDatabase(struct dbVar *dbStructPtr, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int configEvp(struct cryptoVar *cryptoStructPtr, struct conditionBoolsStruct *conditionsStruct);
void encListCallback(const OBJ_NAME *obj, void *arg);
int genEvpSalt(struct cryptoVar *cryptoStructPtr);
int deriveKeys(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr);
int addEntry(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStruct, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int printEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStruct, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int deleteEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct conditionBoolsStruct *conditionsStruct);
int updateEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStruct, struct dbVar *dbStructPtr, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int updateDbEnc(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr);
void genPassWord(struct miscVar *miscStruct, struct textBuf *buffer, struct conditionBoolsStruct *conditionsStruct);
char *getPass(const char *prompt, char *paddedPass);
void allocateBuffers(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *buffer);
bool fileNonExistant(const char *filename);
int returnFileSize(const char *filename);
void cleanUpBuffers();
void signalHandler(int signum);
int sendToClipboard(char *textToSend, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
int printSyntax(char *arg);
int printMACErrMessage(int errMessage);
int verifyCiphertext(unsigned int encryptedBufferLength, unsigned char *encryptedBufferLcl, unsigned char *HMACKeyLcl, char *encCipherNameLcl, unsigned int scryptNFactorLcl, unsigned int scryptRFactorLcl, unsigned int scryptPFactorLcl, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr);
int signCiphertext(unsigned int encryptedBufferLength, unsigned char *encryptedBufferLcl, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr);
int evpDecrypt(EVP_CIPHER_CTX *ctx, int evpInputLength, int *evpOutputLength, unsigned char *encryptedBufferLcl, unsigned char *decryptedBufferLcl);
int evpEncrypt(EVP_CIPHER_CTX *ctx, int evpInputLength, int *evpOutputLength, unsigned char *encryptedBufferLcl, unsigned char *decryptedBufferLcl);
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct miscVar *miscStruct);
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct miscVar *miscStruct);
int constTimeMemCmp(const void *in_a, const void *in_b, size_t len);
void printDbInfo(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr);
void printClipboardMessage(int entriesMatched, struct miscVar *miscStruct, struct conditionBoolsStruct *conditionsStruct);
bool xselIsInstalled(void);
#ifdef HAVE_LIBX11
int targetWinHandler(Display *xDisplay,
                     Window *targetWindow,
                     XEvent XAeventStruct,
                     Atom *windowProperty, Atom targetProperty, unsigned char *passToSend, unsigned long passLength);
int sendWithXlib(char *passToSend, int passLength, int clearTime, struct conditionBoolsStruct *conditionsStruct);
#endif
int regExComp(char *regexPattern, char *stringToCompare, int cflags);
