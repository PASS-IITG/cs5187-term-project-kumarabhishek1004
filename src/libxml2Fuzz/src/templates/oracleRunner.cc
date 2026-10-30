// Differential/metamorphic oracle for Engine 2. Usage: oracleRunner <xmlFile> <chunkSize1,chunkSize2,...>
// Prints key=value lines describing how libxml2 handled the input via several code paths.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>

namespace {

const int parseOptions = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;

void silentGenericError(void *, const char *, ...) {}

std::string readWholeFile(const char *path) {
    std::ifstream input(path, std::ios::binary);
    std::stringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string dumpDocument(xmlDocPtr doc) {
    xmlChar *buffer = nullptr;
    int size = 0;
    xmlDocDumpMemory(doc, &buffer, &size);
    std::string result(buffer ? reinterpret_cast<char *>(buffer) : "", buffer ? size : 0);
    if (buffer) xmlFree(buffer);
    return result;
}

bool parseOneShot(const std::string &data, std::string &serialized) {
    xmlDocPtr doc = xmlReadMemory(data.data(), (int)data.size(), "input.xml", nullptr, parseOptions);
    if (!doc) return false;
    serialized = dumpDocument(doc);
    xmlFreeDoc(doc);
    return true;
}

bool parseInChunks(const std::string &data, size_t chunkSize, std::string &serialized) {
    xmlParserCtxtPtr context = xmlCreatePushParserCtxt(nullptr, nullptr, nullptr, 0, "input.xml");
    if (!context) return false;
    xmlCtxtUseOptions(context, parseOptions);
    for (size_t offset = 0; offset < data.size(); offset += chunkSize) {
        size_t length = std::min(chunkSize, data.size() - offset);
        if (xmlParseChunk(context, data.data() + offset, (int)length, 0) != 0) break;
    }
    xmlParseChunk(context, nullptr, 0, 1);
    bool wellFormed = context->wellFormed != 0 && context->myDoc != nullptr;
    if (wellFormed) serialized = dumpDocument(context->myDoc);
    if (context->myDoc) xmlFreeDoc(context->myDoc);
    xmlFreeParserCtxt(context);
    return wellFormed;
}

bool readWithReader(const std::string &data) {
    xmlTextReaderPtr reader = xmlReaderForMemory(data.data(), (int)data.size(), "input.xml", nullptr, parseOptions);
    if (!reader) return false;
    int status;
    while ((status = xmlTextReaderRead(reader)) == 1) {}
    xmlFreeTextReader(reader);
    return status == 0;
}

std::vector<size_t> parseChunkSizes(const char *text) {
    std::vector<size_t> sizes;
    std::stringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ',')) {
        if (!item.empty()) sizes.push_back((size_t)std::atol(item.c_str()));
    }
    return sizes;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    xmlInitParser();
    xmlSetGenericErrorFunc(nullptr, silentGenericError);
    std::string data = readWholeFile(argv[1]);
    std::vector<size_t> chunkSizes = parseChunkSizes(argc > 2 ? argv[2] : "1,7");

    std::string oneShotOutput;
    bool oneShotWellFormed = parseOneShot(data, oneShotOutput);
    printf("oneShotWellFormed=%d\n", oneShotWellFormed);

    if (oneShotWellFormed) {
        std::string reparsedOutput;
        bool reparseOk = parseOneShot(oneShotOutput, reparsedOutput);
        printf("reparseOk=%d\n", reparseOk);
        printf("roundTripStable=%d\n", reparseOk && reparsedOutput == oneShotOutput);
    }

    for (size_t chunkSize : chunkSizes) {
        std::string chunkedOutput;
        bool chunkedWellFormed = parseInChunks(data, chunkSize, chunkedOutput);
        printf("pushChunk%zuWellFormed=%d\n", chunkSize, chunkedWellFormed);
        if (chunkedWellFormed && oneShotWellFormed) {
            printf("pushChunk%zuSameOutput=%d\n", chunkSize, chunkedOutput == oneShotOutput);
        }
    }

    printf("readerWellFormed=%d\n", readWithReader(data));
    xmlCleanupParser();
    return 0;
}
