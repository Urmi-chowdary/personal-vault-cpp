#ifndef PERMISSIONREQUEST_H
#define PERMISSIONREQUEST_H

#include <string>
#include "DataAsset.h"

// One permission an app asks for. COMPOSITION: it holds a DataAsset.
class PermissionRequest {
private:
    DataAsset asset;

public:
    explicit PermissionRequest(const DataAsset& asset);
    const std::string& getName() const;
    int getSensitivity() const;
    bool isHighlySensitive() const;
};

#endif
