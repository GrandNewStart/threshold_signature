#pragma once
#include <iostream>
#include <vector>

int generatePartialSignature(int share, const std::string& hash);
int aggregateSignatures(const std::vector<std::pair<int, int>>& partialSignatures);
bool verifySignature(int finalSignature, const std::string& message, int privateKey);