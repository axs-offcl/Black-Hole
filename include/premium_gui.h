#pragma once

#include "imgui.h"
#include "imgui_internal.h"
#include <d3d11.h>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>

inline ID3D11PixelShader* g_BlurShader = nullptr;
inline ID3D11ShaderResourceView* g_BlurTex = nullptr;

inline void SafeRelease(IUnknown*& ptr) {
    if (ptr) { ptr->Release(); ptr = nullptr; }
}

inline void GetBackBuffer(IDXGISwapChain* swapChain, ID3D11Device* device, ID3D11DeviceContext* ctx) {
    ID3D11Texture2D* backBuffer = nullptr;
    swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));

    D3D11_TEXTURE2D_DESC desc;
    backBuffer->GetDesc(&desc);
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    ID3D11Texture2D* copyTex = nullptr;
    device->CreateTexture2D(&desc, nullptr, &copyTex);
    ctx->CopyResource(copyTex, backBuffer);

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = desc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = desc.MipLevels;
    srvDesc.Texture2D.MostDetailedMip = 0;

    SafeRelease(reinterpret_cast<IUnknown*&>(g_BlurTex));
    device->CreateShaderResourceView(copyTex, &srvDesc, &g_BlurTex);

    SafeRelease(reinterpret_cast<IUnknown*&>(backBuffer));
    SafeRelease(reinterpret_cast<IUnknown*&>(copyTex));
}

struct ImGui_ImplDX11_Data {
    ID3D11Device* pd3dDevice;
    ID3D11DeviceContext* pd3dDeviceContext;
    IDXGIFactory* pFactory;
    ID3D11Buffer* pVB;
    ID3D11Buffer* pIB;
    ID3D11VertexShader* pVertexShader;
    ID3D11InputLayout* pInputLayout;
    ID3D11Buffer* pVertexConstantBuffer;
    ID3D11PixelShader* pPixelShader;
    ID3D11SamplerState* pFontSampler;
    ID3D11ShaderResourceView* pFontTextureView;
    ID3D11RasterizerState* pRasterizerState;
    ID3D11BlendState* pBlendState;
    ID3D11DepthStencilState* pDepthStencilState;
    int VertexBufferSize;
    int IndexBufferSize;
};

inline void BlurBeginCallback(const ImDrawList* d, const ImDrawCmd* cmd) {
    auto swapChain = reinterpret_cast<IDXGISwapChain*>(cmd->UserCallbackData);
    auto bd = (ImGui_ImplDX11_Data*)ImGui::GetIO().BackendRendererUserData;
    auto* device = bd->pd3dDevice;
    auto* ctx = bd->pd3dDeviceContext;

    if (!g_BlurTex)
        GetBackBuffer(swapChain, device, ctx);

    if (!g_BlurShader) {
        extern unsigned char g_BlurPixelShader[];
        extern unsigned int g_BlurPixelShaderSize;
        device->CreatePixelShader(g_BlurPixelShader, g_BlurPixelShaderSize, NULL, &g_BlurShader);
    }

    ctx->PSSetShader(g_BlurShader, nullptr, 0);
    ctx->PSSetSamplers(0, 1, &bd->pFontSampler);
}

inline void BlurReleaseCallback(const ImDrawList* d, const ImDrawCmd* cmd) {
    SafeRelease(reinterpret_cast<IUnknown*&>(g_BlurTex));
}

inline void DrawBackgroundBlur(ImDrawList* drawList, IDXGISwapChain* swapChain, ImVec2 start, ImVec2 end, int rounding = 0) {
    drawList->AddCallback(BlurBeginCallback, swapChain);
    drawList->AddImageRounded(
        (ImTextureID)g_BlurTex,
        start, end,
        start / ImGui::GetIO().DisplaySize,
        end / ImGui::GetIO().DisplaySize,
        ImColor{ 1.f, 1.f, 1.f, ImGui::GetStyle().Alpha },
        rounding);
    drawList->AddCallback(BlurReleaseCallback, nullptr);
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
}

struct PremiumNotification {
    std::string text;
    float delay;
    float timer = 0.f;
    float alpha = 0.f;
    bool active = true;
};

class PremiumNotificationSystem {
public:
    void add(const std::string& text, float delay = 5.0f) {
        notifications.push_back({ text, delay, 0.f, 0.f, true });
    }

    void render() {
        float dt = ImGui::GetIO().DeltaTime;
        for (int i = 0; i < (int)notifications.size(); ++i) {
            auto& n = notifications[i];
            if (n.active) n.timer += dt;
            if (n.timer >= n.delay) n.active = false;

            n.alpha = ImClamp(n.alpha + (4.0f * dt * (n.active ? 1.f : -1.f)), 0.f, 1.f);

            float textW = ImGui::CalcTextSize(n.text.c_str()).x;
            float padX = 20.f;
            float notifW = textW + padX * 2;
            float notifH = 50.f;

            float screenW = ImGui::GetIO().DisplaySize.x;
            float targetX = screenW - notifW - 20.f;
            float startX = screenW + 10.f;
            float easeT = 1.f - powf(2.f, -8.f * (n.active ? n.alpha : (1.f - n.alpha)));
            float notifX = startX + (targetX - startX) * easeT;

            float notifY = 60.f + i * (notifH + 8.f);

            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, n.alpha);

            ImGui::SetNextWindowPos(ImVec2(notifX, notifY));
            ImGui::SetNextWindowSize(ImVec2(notifW, notifH));

            std::string winId = "##notif_" + std::to_string(i);
            ImGui::Begin(winId.c_str(), nullptr,
                ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings);

            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 wPos = ImGui::GetWindowPos();
            ImVec2 wSize = ImGui::GetWindowSize();
            ImVec2 mn = wPos;
            ImVec2 mx(wPos.x + wSize.x, wPos.y + wSize.y);

            dl->AddRectFilled(mn, mx, IM_COL32(16, 16, 22, 240), 8.0f);

            float pct = (n.delay > 0.f) ? (n.timer / n.delay) : 0.f;
            if (pct > 1.f) pct = 1.f;
            ImVec2 barMin(mn.x + 12.f, mx.y - 12.f);
            ImVec2 barMax(mx.x - 12.f, mx.y - 6.f);
            dl->AddRectFilled(barMin, barMax, IM_COL32(30, 30, 40, 255), 10.f);
            ImVec2 fillMax(barMin.x + (barMax.x - barMin.x) * (1.f - pct), barMax.y);
            dl->AddRectFilled(barMin, fillMax, IM_COL32(0, 204, 148, 255), 10.f);

            ImVec2 textPos(mn.x + 14.f, mn.y + (wSize.y - ImGui::GetTextLineHeight()) * 0.5f - 3.f);
            dl->AddText(textPos, IM_COL32(235, 235, 240, 255), n.text.c_str());

            ImGui::End();
            ImGui::PopStyleVar(2);
        }

        notifications.erase(
            std::remove_if(notifications.begin(), notifications.end(),
                [](const PremiumNotification& n) { return !n.active && n.alpha <= 0.01f; }),
            notifications.end());
    }

    std::vector<PremiumNotification> notifications;
};

inline bool PremiumToggle(const char* label, bool* value) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiID id = window->GetID(label);

    float width = ImGui::GetContentRegionAvail().x;
    float height = 30.0f;
    ImVec2 pos = window->DC.CursorPos;
    ImRect totalBB(pos, ImVec2(pos.x + width, pos.y + height));

    ImGui::ItemSize(totalBB, 0.0f);
    if (!ImGui::ItemAdd(totalBB, id)) return false;

    bool pressed = ImGui::ButtonBehavior(totalBB, id, nullptr, nullptr);

    struct ToggleState {
        float circleOffset = 0.0f;
        ImVec4 bgColor = ImVec4(0.12f, 0.12f, 0.16f, 1.0f);
        ImVec4 circleColor = ImVec4(0.25f, 0.25f, 0.30f, 1.0f);
    };

    ToggleState* state = (ToggleState*)ImGui::GetStateStorage()->GetVoidPtr(id);
    if (!state) {
        state = new ToggleState();
        ImGui::GetStateStorage()->SetVoidPtr(id, state);
    }

    if (pressed) {
        *value = !(*value);
        ImGui::MarkItemEdited(id);
    }

    float lerpSpeed = ImGui::GetIO().DeltaTime * 12.0f;
    state->circleOffset = ImLerp(state->circleOffset, *value ? 22.0f : 4.0f, lerpSpeed);
    state->bgColor = ImLerp(state->bgColor, *value ? ImVec4(0.0f, 0.60f, 0.44f, 1.0f) : ImVec4(0.12f, 0.12f, 0.16f, 1.0f), lerpSpeed);
    state->circleColor = ImLerp(state->circleColor, *value ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f) : ImVec4(0.40f, 0.40f, 0.45f, 1.0f), lerpSpeed);

    ImDrawList* dl = window->DrawList;
    ImVec2 toggleMin(pos.x + width - 44.0f, pos.y + 3.0f);
    ImVec2 toggleMax(pos.x + width - 4.0f, pos.y + height - 3.0f);

    dl->AddRectFilled(toggleMin, toggleMax, ImGui::ColorConvertFloat4ToU32(state->bgColor), 100.0f);

    float circleRadius = 8.0f;
    float circleY = (toggleMin.y + toggleMax.y) * 0.5f;
    float circleX = toggleMin.x + state->circleOffset;
    dl->AddCircleFilled(ImVec2(circleX, circleY), circleRadius, ImGui::ColorConvertFloat4ToU32(state->circleColor), 100);

    ImVec2 textPos(pos.x + 4.0f, pos.y + (height - ImGui::GetTextLineHeight()) * 0.5f);
    dl->AddText(textPos, IM_COL32(235, 235, 240, 255), label);

    return pressed;
}

inline bool PremiumButton(const char* label, const ImVec2& size, ImVec4 baseColor) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiID id = window->GetID(label);
    ImVec2 pos = window->DC.CursorPos;
    ImRect totalBB(pos, ImVec2(pos.x + size.x, pos.y + size.y));

    ImGui::ItemSize(totalBB, 0.0f);
    if (!ImGui::ItemAdd(totalBB, id)) return false;

    bool hovered, held, pressed = ImGui::ButtonBehavior(totalBB, id, &hovered, &held);
    if (pressed) ImGui::MarkItemEdited(id);

    struct BtnState {
        ImVec4 color;
    };
    BtnState* state = (BtnState*)ImGui::GetStateStorage()->GetVoidPtr(id);
    if (!state) {
        state = new BtnState();
        state->color = baseColor;
        ImGui::GetStateStorage()->SetVoidPtr(id, state);
    }

    ImVec4 targetColor = held ? ImVec4(baseColor.x * 0.7f, baseColor.y * 0.7f, baseColor.z * 0.7f, baseColor.w) :
        hovered ? ImVec4(baseColor.x * 1.2f, baseColor.y * 1.2f, baseColor.z * 1.2f, baseColor.w) :
        baseColor;
    targetColor.x = ImMin(targetColor.x, 1.0f);
    targetColor.y = ImMin(targetColor.y, 1.0f);
    targetColor.z = ImMin(targetColor.z, 1.0f);

    float lerpSpeed = ImGui::GetIO().DeltaTime * 10.0f;
    state->color = ImLerp(state->color, targetColor, lerpSpeed);

    ImDrawList* dl = window->DrawList;
    dl->AddRectFilled(totalBB.Min, totalBB.Max, ImGui::ColorConvertFloat4ToU32(state->color), 6.0f);

    ImVec2 textSize = ImGui::CalcTextSize(label);
    ImVec2 textPos(totalBB.Min.x + (size.x - textSize.x) * 0.5f, totalBB.Min.y + (size.y - textSize.y) * 0.5f);
    dl->AddText(textPos, IM_COL32(255, 255, 255, 255), label);

    return pressed;
}

inline void PremiumTooltip(const char* title, const char* desc) {
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 10));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f);

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.95f, 1.0f, 1.0f));
        ImGui::TextUnformatted(title);
        ImGui::PopStyleColor();

        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.65f, 0.65f, 0.72f, 1.0f));
        ImGui::TextUnformatted(desc);
        ImGui::PopStyleColor();

        ImGui::PopStyleVar(2);
        ImGui::EndTooltip();
    }
}
