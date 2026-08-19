#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "impact_analyzer.h"

void SelectFile(HWND hwnd);
void SelectFolder(HWND hwnd);
void PerformDeletion(const std::wstring& path, HWND hwnd);
void PerformLeftoverClean(const std::vector<BlackHole::LeftoverRef>& items,
                          const std::vector<bool>& checked, HWND hwnd);
