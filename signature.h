#pragma once
#include <iostream>
#include <vector>

std::vector<int> generatePartialSignatures(const std::vector<std::pair<int, int>>& shares, const std::string& message);
int aggregateSignatures(const std::vector<std::pair<int, int>>& partialSignatures);
bool verifySignature(int finalSignature, const std::string& message, int privateKey);