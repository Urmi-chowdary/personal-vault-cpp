#include "PermissionRequest.h"

PermissionRequest::PermissionRequest(const DataAsset& asset) : asset(asset) {}
const std::string& PermissionRequest::getName() const { return asset.getName(); }
int PermissionRequest::getSensitivity() const { return asset.getSensitivity(); }
bool PermissionRequest::isHighlySensitive() const { return asset.isHighlySensitive(); }
