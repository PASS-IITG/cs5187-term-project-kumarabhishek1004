// Hand-written reference harness: random DOM mutation sequences + allocation-failure injection + save options.
// Ownership rules respected here (important: most "bugs" in LLM harnesses are ownership mistakes):
//  - Only ELEMENT nodes are tracked (xmlAddChild may free/merge text nodes).
//  - Unlinked or freshly created nodes are "orphans" and are freed by us with xmlFreeNode before xmlFreeDoc.
//  - A node is never added below itself (cycle check) and namespaces are only declared on the node using them.
#include <cstddef>
#include <cstdint>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>

#include "fuzzAllocator.h"

namespace {

const size_t maxOperations = 64;
const char *const nodeNames[] = {"a", "b", "item", "root2", "x:y", "longerElementName"};
const char *const textValues[] = {"", "text", "a&b", "<>", "\xc3\xa9"};
const char *const nsUris[] = {"urn:one", "urn:two", "http://example.com/ns"};
const char *const nsPrefixes[] = {"p", "q", "x"};

void silentGenericError(void *, const char *, ...) {}

void collectElements(xmlNodePtr start, std::vector<xmlNodePtr> &output) {
    for (xmlNodePtr current = start; current != nullptr && output.size() < 256; current = current->next) {
        if (current->type == XML_ELEMENT_NODE) {
            output.push_back(current);
            collectElements(current->children, output);
        }
        if (current == start && start->parent == nullptr) break;  // orphan root: do not walk its siblings
    }
}

bool isSelfOrDescendant(xmlNodePtr ancestor, xmlNodePtr candidate) {
    for (xmlNodePtr current = candidate; current != nullptr; current = current->parent) {
        if (current == ancestor) return true;
    }
    return false;
}

void removeFromOrphans(std::vector<xmlNodePtr> &orphans, xmlNodePtr node) {
    for (size_t index = 0; index < orphans.size(); index++) {
        if (orphans[index] == node) {
            orphans.erase(orphans.begin() + index);
            return;
        }
    }
}

template <typename T>
T pickFrom(FuzzedDataProvider &provider, const std::vector<T> &items) {
    return items[provider.ConsumeIntegralInRange<size_t>(0, items.size() - 1)];
}

void saveWithRandomOptions(FuzzedDataProvider &provider, xmlDocPtr doc) {
    int allowedOptions = XML_SAVE_FORMAT | XML_SAVE_NO_DECL | XML_SAVE_NO_EMPTY | XML_SAVE_AS_XML | XML_SAVE_WSNONSIG;
    int chosenOptions = provider.ConsumeIntegral<uint8_t>() & allowedOptions;
    xmlBufferPtr buffer = xmlBufferCreate();
    if (buffer == nullptr) return;
    xmlSaveCtxtPtr saveContext = xmlSaveToBuffer(buffer, "UTF-8", chosenOptions);
    if (saveContext != nullptr) {
        xmlSaveDoc(saveContext, doc);
        xmlSaveClose(saveContext);
    }
    xmlBufferFree(buffer);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    fuzzInstallAllocator();
    xmlInitParser();
    xmlSetGenericErrorFunc(nullptr, silentGenericError);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 4096) return 0;
    FuzzedDataProvider provider(data, size);

    bool injectAllocationFailure = provider.ConsumeBool();
    uint32_t failureIndex = provider.ConsumeIntegralInRange<uint32_t>(0, 400);
    if (injectAllocationFailure) fuzzArmAllocFailure(failureIndex);

    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    xmlNodePtr root = doc ? xmlNewDocNode(doc, nullptr, BAD_CAST "root", nullptr) : nullptr;
    if (root) xmlDocSetRootElement(doc, root);
    std::vector<xmlNodePtr> orphans;

    for (size_t operationCount = 0; doc && root && operationCount < maxOperations && provider.remaining_bytes() > 0;
         operationCount++) {
        std::vector<xmlNodePtr> attached;
        collectElements(root, attached);
        switch (provider.ConsumeIntegralInRange<int>(0, 9)) {
            case 0: {  // create orphan element
                xmlNodePtr created = xmlNewDocNode(doc, nullptr, BAD_CAST provider.PickValueInArray(nodeNames), nullptr);
                if (created) orphans.push_back(created);
                break;
            }
            case 1: {  // attach orphan as child of an attached node or another orphan
                if (orphans.empty()) break;
                xmlNodePtr child = pickFrom(provider, orphans);
                std::vector<xmlNodePtr> parents = attached;
                for (xmlNodePtr orphanParent : orphans) parents.push_back(orphanParent);
                xmlNodePtr parent = pickFrom(provider, parents);
                if (isSelfOrDescendant(child, parent)) break;  // would create a cycle
                removeFromOrphans(orphans, child);
                if (xmlAddChild(parent, child) == nullptr) orphans.push_back(child);
                break;
            }
            case 2: {  // unlink an attached non-root node
                if (attached.size() < 2) break;
                xmlNodePtr victim = attached[provider.ConsumeIntegralInRange<size_t>(1, attached.size() - 1)];
                xmlUnlinkNode(victim);
                orphans.push_back(victim);
                break;
            }
            case 3: {  // replace attached non-root node with orphan
                if (attached.size() < 2 || orphans.empty()) break;
                xmlNodePtr target = attached[provider.ConsumeIntegralInRange<size_t>(1, attached.size() - 1)];
                xmlNodePtr replacement = pickFrom(provider, orphans);
                if (isSelfOrDescendant(replacement, target)) break;
                removeFromOrphans(orphans, replacement);
                xmlNodePtr replaced = xmlReplaceNode(target, replacement);
                if (replaced) orphans.push_back(replaced); else orphans.push_back(replacement);
                break;
            }
            case 4: {  // set content (frees the node's children)
                xmlNodePtr node = pickFrom(provider, attached);
                xmlNodeSetContent(node, BAD_CAST provider.PickValueInArray(textValues));
                break;
            }
            case 5: {  // attribute set
                xmlNodePtr node = pickFrom(provider, attached);
                // Unprefixed names only: a prefixed name would bind the attribute to an ancestor's namespace,
                // which dangles after the node is moved unless xmlReconciliateNs is called (documented behaviour).
                xmlSetProp(node, BAD_CAST provider.PickValueInArray({"id", "class", "title"}),
                           BAD_CAST provider.PickValueInArray(textValues));
                break;
            }
            case 6: {  // namespace declared and used on the same node
                xmlNodePtr node = pickFrom(provider, attached);
                xmlNsPtr ns = xmlNewNs(node, BAD_CAST provider.PickValueInArray(nsUris),
                                       BAD_CAST provider.PickValueInArray(nsPrefixes));
                if (ns) xmlSetNs(node, ns);
                break;
            }
            case 7: {  // deep copy of an attached node becomes an orphan
                xmlNodePtr copy = xmlCopyNode(pickFrom(provider, attached), 1);
                if (copy) orphans.push_back(copy);
                break;
            }
            case 8: {  // rename
                xmlNodeSetName(pickFrom(provider, attached), BAD_CAST provider.PickValueInArray(nodeNames));
                break;
            }
            case 9: {  // insert orphan as sibling of an attached non-root node
                if (attached.size() < 2 || orphans.empty()) break;
                xmlNodePtr anchor = attached[provider.ConsumeIntegralInRange<size_t>(1, attached.size() - 1)];
                xmlNodePtr sibling = pickFrom(provider, orphans);
                if (isSelfOrDescendant(sibling, anchor)) break;
                removeFromOrphans(orphans, sibling);
                xmlNodePtr added = provider.ConsumeBool() ? xmlAddNextSibling(anchor, sibling)
                                                          : xmlAddPrevSibling(anchor, sibling);
                if (added == nullptr) orphans.push_back(sibling);
                break;
            }
        }
    }

    if (doc) saveWithRandomOptions(provider, doc);

    fuzzDisarmAllocFailure();
    for (xmlNodePtr orphan : orphans) xmlFreeNode(orphan);
    if (doc) xmlFreeDoc(doc);
    return 0;
}
