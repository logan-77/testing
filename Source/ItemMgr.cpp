#include "stdafx.h"

#include <GWCA/Constants/Constants.h>
#include <GWCA/Constants/ItemIDs.h>

#include <GWCA/Packets/StoC.h>

#include <GWCA/Context/GameContext.h>
#include <GWCA/Context/AccountContext.h>
#include <GWCA/Context/ItemContext.h>
#include <GWCA/Context/WorldContext.h>

#include <GWCA/Utilities/Hooker.h>
#include <GWCA/Utilities/Hook.h>
#include <GWCA/Utilities/Scanner.h>

#include <GWCA/GameEntities/Item.h>
#include <GWCA/GameEntities/Agent.h>
#include <GWCA/GameEntities/Map.h>

#include <GWCA/Managers/MapMgr.h>
#include <GWCA/Managers/ItemMgr.h>
#include <GWCA/Managers/Module.h>
#include <GWCA/Managers/StoCMgr.h>
#include <GWCA/Managers/AgentMgr.h>
#include <GWCA/Managers/UIMgr.h>

namespace {
    using namespace GW;
    using namespace Items;

    uint32_t* storage_open_addr = 0;
    enum ItemClickType : uint32_t {
        ItemClickType_Add           = 2, // (when you load / open chest)
        ItemClickType_Click         = 5,
        ItemClickType_Release       = 7,
        ItemClickType_DoubleClick   = 8,
        ItemClickType_Move          = 9,
        ItemClickType_DragStart     = 10,
        ItemClickType_DragStop      = 12,
    };

    struct ItemClickParam {
        uint32_t unk0;
        uint32_t slot;
        uint32_t type;
    };

    Array<PvPItemUpgradeInfo> unlocked_pvp_item_upgrade_array;
    Array<PvPItemInfo> pvp_item_array;
    Array<CompositeModelInfo>* composite_model_info_array;

    typedef void(__cdecl* GetPvPItemUpgradeInfoName_pt)(uint32_t pvp_item_upgrade_id, uint32_t name_or_description, wchar_t** name_out,wchar_t** description_out);
    GetPvPItemUpgradeInfoName_pt GetPvPItemUpgradeInfoName_Func = nullptr;

    typedef void (__fastcall *ItemClick_pt)(uint32_t *bag_id, void *edx, ItemClickParam *param);
    ItemClick_pt RetItemClick = 0;
    ItemClick_pt ItemClick_Func = 0;

    // General purpose "void function that does something with this id"
    typedef void(__cdecl* DoAction_pt)(uint32_t identifier);

    DoAction_pt DropGold_Func = 0;
    DoAction_pt OpenLockedChest_Func = 0;
    DoAction_pt DestroyItem_Func = 0;

    HookEntry OnUseItem_Entry;
    DoAction_pt UseItem_Func = 0;
    DoAction_pt UseItem_Ret = 0;

    bool CanAccessXunlaiChest() {
        if (GW::Map::GetInstanceType() != GW::Constants::InstanceType::Outpost)
            return false;
        // TODO: Any way to tell if current character has paid 50g to unlock storage?
        const auto map = GW::Map::GetCurrentMapInfo();
        return map && map->region != GW::Region_Presearing;
    }
    bool IsStorageBag(const GW::Bag* bag) {
        return bag && bag->bag_type == GW::Constants::BagType::Storage;
    }
    bool IsStorageItem(const GW::Item* item) {
        return item && IsStorageBag(item->bag);
    }


    void OnUseItem(uint32_t item_id) {
        GW::Hook::EnterHook();
        UI::SendUIMessage(UI::UIMessage::kSendUseItem, (void*)item_id);
        GW::Hook::LeaveHook();
    };
    void OnUseItem_UIMessage(GW::HookStatus* status, UI::UIMessage message_id, void* wparam, void*) {
        GWCA_ASSERT(message_id == UI::UIMessage::kSendUseItem && wparam);
        if (!status->blocked) {
            UseItem_Ret((uint32_t)wparam);
        }
    }

    HookEntry OnPingWeaponSet_Entry;
    typedef void(__cdecl* PingWeaponSet_pt)(uint32_t agent_id, uint32_t weapon_item_id, uint32_t offhand_item_id);
    PingWeaponSet_pt PingWeaponSet_Func = 0;
    PingWeaponSet_pt PingWeaponSet_Ret = 0;

    void OnPingWeaponSet(uint32_t agent_id, uint32_t weapon_item_id, uint32_t offhand_item_id) {
        GW::Hook::EnterHook();
        const auto packet = UI::UIPacket::kSendPingWeaponSet{agent_id, weapon_item_id, offhand_item_id};
        // Pass this through UI, we'll pick it up in OnSendDialog_UIMessage
        UI::SendUIMessage(UI::UIMessage::kSendPingWeaponSet, (void*)&packet);
        GW::Hook::LeaveHook();
    };
    void OnPingWeaponSet_UIMessage(GW::HookStatus* status, UI::UIMessage message_id, void* wparam, void*) {
        GWCA_ASSERT(message_id == UI::UIMessage::kSendPingWeaponSet && wparam);
        const auto packet = static_cast<UI::UIPacket::kSendPingWeaponSet*>(wparam);
        if (!status->blocked) {
            PingWeaponSet_Ret(packet->agent_id, packet->weapon_item_id, packet->offhand_item_id);
        }
    }

    HookEntry OnMoveItem_Entry;
    typedef void(__cdecl* MoveItem_pt)(uint32_t item_id, uint32_t quantity, uint32_t bag_index, uint32_t slot);
    MoveItem_pt MoveItem_Func = 0;
    MoveItem_pt MoveItem_Ret = 0;
    struct MoveItem_UIMessage { 
        uint32_t item_id;
        uint32_t quantity;
        uint32_t bag_index; // equal to bag_id() - 1
        uint32_t slot;
    };
    void OnMoveItem(uint32_t item_id, uint32_t quantity, uint32_t bag_index, uint32_t slot) {
        GW::Hook::EnterHook();
        MoveItem_UIMessage packet = { item_id, quantity, bag_index, slot };
        UI::SendUIMessage(UI::UIMessage::kSendMoveItem, &packet);
        GW::Hook::LeaveHook();
    };
    void OnMoveItem_UIMessage(GW::HookStatus* status, UI::UIMessage message_id, void* wparam, void*) {
        GWCA_ASSERT(message_id == UI::UIMessage::kSendMoveItem && wparam);
        const auto packet = static_cast<MoveItem_UIMessage*>(wparam);
        // Make sure the user is allowed to move the item by the game
        if (!status->blocked && !CanAccessXunlaiChest()) {
            const auto item = Items::GetItemById(packet->item_id);
            const auto bag = Items::GetBagByIndex(packet->bag_index);
            if (IsStorageItem(item) || IsStorageBag(bag))
                status->blocked = true;
        }
        if (!status->blocked) {
            MoveItem_Ret(packet->item_id, packet->quantity, packet->bag_index, packet->slot);
        }
    }

    typedef void(__cdecl* EquipItem_pt)(uint32_t item_id, uint32_t agent_id);
    EquipItem_pt EquipItem_Func = 0;

    typedef void(__cdecl* DropItem_pt)(uint32_t item_id, uint32_t quantity);
    DropItem_pt DropItem_Func = 0;

    typedef void(__cdecl* ChangeEquipmentVisibility_pt)(uint32_t equipment_state, uint32_t equip_type);
    ChangeEquipmentVisibility_pt ChangeEquipmentVisibility_Func = 0;

    typedef void(__cdecl* ChangeGold_pt)(uint32_t character_gold, uint32_t storage_gold);
    ChangeGold_pt ChangeGold_Func = 0;
    ChangeGold_pt ChangeGold_Ret = 0;

    void __cdecl OnChangeGold(uint32_t character_gold, uint32_t storage_gold) {
        HookBase::EnterHook();
        if (CanAccessXunlaiChest())
            ChangeGold_Ret(character_gold, storage_gold);
        HookBase::LeaveHook();
    }

    SalvageSessionInfo* salvage_context = nullptr;

    GW::UI::UIInteractionCallback OnSalvagePopup_UICallback_Func = 0, OnSalvagePopup_UICallback_Ret = 0;

    GW::UI::UIInteractionCallback InventorySlot_UICallback_Func = 0;

    void OnSalvagePopup_UICallback(GW::UI::InteractionMessage* message, void* wParam, void* lParam) {
        GW::Hook::EnterHook();
        OnSalvagePopup_UICallback_Ret(message, wParam, lParam);
        switch (message->message_id) {
        case GW::UI::UIMessage::kInitFrame:
            salvage_context = *(SalvageSessionInfo**)message->wParam;
            break;
        case GW::UI::UIMessage::kDestroyFrame:
            salvage_context = nullptr;
            break;
        }
        GW::Hook::LeaveHook();
    }


    ItemFormula* item_formulas = nullptr;
    uint32_t item_formula_count = 0;

    uint32_t GetSalvageSessionId() {
        const auto w = GetWorldContext();
        return w ? w->salvage_session_id : 0;
    }

    std::unordered_map<HookEntry *, ItemClickCallback> ItemClick_callbacks;
    void __fastcall OnItemClick(uint32_t* bag_index, void *edx, ItemClickParam *param) {
        HookBase::EnterHook();
        if (!(bag_index && param)) {
            RetItemClick(bag_index, edx, param);
            HookBase::LeaveHook();
            return;
        }

        uint32_t slot = param->slot - 2; // for some reason the slot is offset by 2
        GW::HookStatus status;
        Bag* bag = GetBagByIndex(*bag_index);
        if (IsStorageBag(bag) && !CanAccessXunlaiChest())
            status.blocked = true;
        if (bag) {
            for (auto& it : ItemClick_callbacks) {
                it.second(&status, param->type, slot, bag);
                ++status.altitude;
            }
        }
        if (!status.blocked)
            RetItemClick(bag_index, edx, param);
        HookBase::LeaveHook();
    }

    void Init() {

        DWORD address = 0;

        address = Scanner::Find("\xC7\x00\x0F\x00\x00\x00\x89\x48\x14", "xxxxxxxxx", -0x28);
        if (Scanner::IsValidPtr(*(uintptr_t*)address))
            storage_open_addr = *(uint32_t**)address;

        ItemClick_Func = (ItemClick_pt)Scanner::ToFunctionStart(Scanner::Find("\x8B\x48\x08\x83\xEA\x00\x0F\x84", "xxxxxxxx"));

        address = Scanner::Find("\x0f\xb6\x40\x04\x83\xc0\xf8", "xxxxxxx", 0x1f);
        UseItem_Func = (DoAction_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::Find("\x83\xc4\x04\x85\xc0\x0f?????\x8d\x45\x0c", "xxxxxx?????xxx");
        if (Scanner::IsValidPtr(address, ScannerSection::Section_TEXT)) {
            EquipItem_Func = (EquipItem_pt)Scanner::FunctionFromNearCall(address + 0x1e);
            MoveItem_Func = (MoveItem_pt)Scanner::FunctionFromNearCall(address + 0x6e);
        }


        // @Cleanup: All of these functions could be done via UI messages
        address = Scanner::FindAssertion("\\Code\\Gw\\Ui\\Game\\GmView.cpp", "param.notifyData",0,0);
        if (Scanner::IsValidPtr(address, ScannerSection::Section_TEXT)) {
            const auto assertion_address = address;
            address = Scanner::FindInRange("\xe8", "x", 0, assertion_address + 0xf, assertion_address + 0x64);
            DropGold_Func = (DoAction_pt)Scanner::FunctionFromNearCall(address);
        }

        OnSalvagePopup_UICallback_Func = (UI::UIInteractionCallback)Scanner::ToFunctionStart(Scanner::FindAssertion("InvSalvage.cpp","m_toolId",0,0),0x200);
        InventorySlot_UICallback_Func = (UI::UIInteractionCallback)Scanner::ToFunctionStart(Scanner::FindAssertion("InvSlot.cpp", "!m_dragOverlayTexture", 0, 0), 0xfff);

        address = Scanner::Find("\x83\xc4\x40\x6a\x00\x6a\x19", "xxxxxxx", -0x4e);
        DropItem_Func = (DropItem_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::Find("\x83\x78\x08\x0a\x75\x10", "xxxxxx", 0xe);
        DestroyItem_Func = (DoAction_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::Find("\x8b\x42\x04\x51\x23\xc1","xxxxxx",0x7);
        ChangeEquipmentVisibility_Func = (ChangeEquipmentVisibility_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::Find("\x68\x21\x03\x00\x00\x89\x45\xfc", "xxxxxxxx", 0x3a);
        ChangeGold_Func = (ChangeGold_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::Find("\x83\xc9\x01\x89\x4b\x24", "xxxxxx", 0x28);
        OpenLockedChest_Func = (DoAction_pt)Scanner::FunctionFromNearCall(address);

        address = Scanner::FindAssertion("\\Code\\Gw\\Ui\\Game\\GmWeaponBar.cpp", "slotIndex < ITEM_PLAYER_EQUIP_SETS", 0,0x128);
        PingWeaponSet_Func = (PingWeaponSet_pt)Scanner::FunctionFromNearCall(address);

        address = GW::Scanner::FindAssertion("\\Code\\Gw\\Const\\ConstItemPvp.cpp", "unlockIndex < ITEM_PVP_UNLOCK_COUNT",0,0);
        if (address) {
            unlocked_pvp_item_upgrade_array.m_buffer = *(PvPItemUpgradeInfo**)(address + 0x15);
            unlocked_pvp_item_upgrade_array.m_size = *(size_t*)(address - 0xb);
        }

        address = GW::Scanner::FindAssertion("\\Code\\Gw\\Const\\ConstItemPvp.cpp", "index < ITEM_PVP_ITEM_COUNT",0,0);
        if (address) {
            pvp_item_array.m_buffer = *(PvPItemInfo**)(address + 0x15);
            pvp_item_array.m_size = *(size_t*)(address - 0xb);
        }

        address = GW::Scanner::FindAssertion("\\Code\\Gw\\Composite\\Data\\CpsData.cpp", "id < s_items.Count()",0,-0xb);
        if (address) {
            address = (*(uintptr_t*)address) - 8;
            composite_model_info_array = (Array<CompositeModelInfo>*)address;
        }

        address = GW::Scanner::Find("\xff\x75\x0c\x81\xc1\xb4\x00\x00\x00","xxxxxxxxx", -0x11);
        if (GW::Scanner::IsValidPtr(address, GW::ScannerSection::Section_TEXT)) {
            GetPvPItemUpgradeInfoName_Func = (GetPvPItemUpgradeInfoName_pt)address;
        }

        address = GW::Scanner::FindAssertion("\\Code\\Gw\\Const\\ConstItem.cpp", "formula < ITEM_FORMULAS",0,0);
        if (address) {
            item_formulas = *(ItemFormula**)(address + 0x15);
            item_formula_count = *(uint32_t*)(address + -0xb);
        }
        GWCA_INFO("[SCAN] OnSalvagePopup_UICallback_Func = %p", OnSalvagePopup_UICallback_Func);
        GWCA_INFO("[SCAN] InventorySlot_UICallback_Func = %p", InventorySlot_UICallback_Func);
        GWCA_INFO("[SCAN] item_formulas = %p, item_count = %p", item_formulas, item_formula_count);
        GWCA_INFO("[SCAN] StorageOpenPtr = %p", storage_open_addr);
        GWCA_INFO("[SCAN] OnItemClick Function = %p", ItemClick_Func);
        GWCA_INFO("[SCAN] UseItem Function = %p", UseItem_Func);
        GWCA_INFO("[SCAN] EquipItem Function = %p", EquipItem_Func);
        GWCA_INFO("[SCAN] MoveItem Function = %p", MoveItem_Func);
        GWCA_INFO("[SCAN] DropGold Function = %p", DropGold_Func);
        GWCA_INFO("[SCAN] DropItem Function = %p", DropItem_Func);
        GWCA_INFO("[SCAN] DestroyItem_Func Function = %p", DestroyItem_Func);
        GWCA_INFO("[SCAN] ChangeEquipmentVisibility Function = %p", ChangeEquipmentVisibility_Func);
        GWCA_INFO("[SCAN] ChangeGold Function = %p", ChangeGold_Func);
        GWCA_INFO("[SCAN] OpenLockedChest Function = %p", OpenLockedChest_Func);
        GWCA_INFO("[SCAN] PingWeaponSet_Func = %p", PingWeaponSet_Func);
        GWCA_INFO("[SCAN] unlocked_pvp_item_upgrade_array.m_buffer = %p", unlocked_pvp_item_upgrade_array.m_buffer);
        GWCA_INFO("[SCAN] unlocked_pvp_item_upgrade_array.m_size = %p", unlocked_pvp_item_upgrade_array.m_size);
        GWCA_INFO("[SCAN] GetPvPItemUpgradeInfoName_Func = %p", GetPvPItemUpgradeInfoName_Func);
#ifdef _DEBUG
        GWCA_ASSERT(OnSalvagePopup_UICallback_Func);
        GWCA_ASSERT(InventorySlot_UICallback_Func);
        GWCA_ASSERT(item_formulas);
        GWCA_ASSERT(storage_open_addr);
        GWCA_ASSERT(ItemClick_Func);
        GWCA_ASSERT(EquipItem_Func);
        GWCA_ASSERT(UseItem_Func);
        GWCA_ASSERT(MoveItem_Func);
        GWCA_ASSERT(DropGold_Func);
        GWCA_ASSERT(DropItem_Func);
        GWCA_ASSERT(ChangeEquipmentVisibility_Func);
        GWCA_ASSERT(ChangeGold_Func);
        GWCA_ASSERT(OpenLockedChest_Func);
        GWCA_ASSERT(PingWeaponSet_Func);
        GWCA_ASSERT(unlocked_pvp_item_upgrade_array.m_buffer);
        GWCA_ASSERT(unlocked_pvp_item_upgrade_array.m_size);
        GWCA_ASSERT(GetPvPItemUpgradeInfoName_Func);
        GWCA_ASSERT(DestroyItem_Func);
#endif

        if (OnSalvagePopup_UICallback_Func)
            HookBase::CreateHook((void**)&OnSalvagePopup_UICallback_Func, OnSalvagePopup_UICallback, (void**)&OnSalvagePopup_UICallback_Ret);

        if(ItemClick_Func)
            HookBase::CreateHook((void**)&ItemClick_Func, OnItemClick, (void**)&RetItemClick);
        if (PingWeaponSet_Func) {
            HookBase::CreateHook((void**)&PingWeaponSet_Func, OnPingWeaponSet, (void**)&PingWeaponSet_Ret);
            UI::RegisterUIMessageCallback(&OnPingWeaponSet_Entry, UI::UIMessage::kSendPingWeaponSet, OnPingWeaponSet_UIMessage, 0x1);
        }
        if (MoveItem_Func) {
            HookBase::CreateHook((void**)&MoveItem_Func, OnMoveItem, (void**)&MoveItem_Ret);
            UI::RegisterUIMessageCallback(&OnMoveItem_Entry, UI::UIMessage::kSendMoveItem, OnMoveItem_UIMessage, 0x1);
        }
        if (UseItem_Func) {
            HookBase::CreateHook((void**)&UseItem_Func, OnUseItem, (void**)&UseItem_Ret);
            UI::RegisterUIMessageCallback(&OnUseItem_Entry, UI::UIMessage::kSendUseItem, OnUseItem_UIMessage, 0x1);
        }
        if (ChangeGold_Func) {
            HookBase::CreateHook((void**)&ChangeGold_Func, OnChangeGold, (void**)&ChangeGold_Ret);
        }
    }

    void EnableHooks() {
        if(OnSalvagePopup_UICallback_Func)
            HookBase::EnableHooks(OnSalvagePopup_UICallback_Func);
        if (ItemClick_Func)
            HookBase::EnableHooks(ItemClick_Func);
        if (PingWeaponSet_Func)
            HookBase::EnableHooks(PingWeaponSet_Func);
        if (MoveItem_Func)
            HookBase::EnableHooks(MoveItem_Func);
        if (UseItem_Func)
            HookBase::EnableHooks(UseItem_Func);
    }

    void DisableHooks() {
        if(OnSalvagePopup_UICallback_Func)
            HookBase::DisableHooks(OnSalvagePopup_UICallback_Func);
        if (ItemClick_Func)
            HookBase::DisableHooks(ItemClick_Func);
        if (PingWeaponSet_Func)
            HookBase::DisableHooks(PingWeaponSet_Func);
        if (MoveItem_Func)
            HookBase::DisableHooks(MoveItem_Func);
        if (UseItem_Func)
            HookBase::DisableHooks(UseItem_Func);
        if (ChangeGold_Func)
            HookBase::DisableHooks(ChangeGold_Func);
    }

    void Exit() {
        HookBase::RemoveHook(OnSalvagePopup_UICallback_Func);
        HookBase::RemoveHook(ItemClick_Func);
        HookBase::RemoveHook(PingWeaponSet_Func);
        HookBase::RemoveHook(MoveItem_Func);
        HookBase::RemoveHook(UseItem_Func);
        HookBase::RemoveHook(ChangeGold_Func);
    }
}

namespace GW {

    Module ItemModule = {
        "ItemModule",   // name
        NULL,           // param
        ::Init,         // init_module
        ::Exit,         // exit_module
        ::EnableHooks,           // enable_hooks
        ::DisableHooks,           // disable_hooks
    };

    GW::ItemModifier* Item::GetModifier(const uint32_t identifier) const
    {
        for (size_t i = 0; i < mod_struct_size; i++) {
            GW::ItemModifier* mod = &mod_struct[i];
            if (mod->identifier() == identifier) {
                return mod;
            }
        }
        return nullptr;
    }

    bool Item::GetIsZcoin() const {
        if (model_file_id == 31202) return true; // Copper
        if (model_file_id == 31203) return true; // Gold
        if (model_file_id == 31204) return true; // Silver
        return false;
    }

    bool Item::GetIsMaterial() const {
        if (type == Constants::ItemType::Materials_Zcoins
            && !GetIsZcoin()) {
            return true;
        }
        return false;
    }
    namespace Items {

        SalvageSessionInfo* GetSalvageSessionInfo() {
            return salvage_context;
        }

        void OpenXunlaiWindow(bool anniversary_pane_unlocked) {
            Packet::StoC::DataWindow pack{};
            pack.agent = 0;
            pack.type = 0;
            pack.data = anniversary_pane_unlocked ? 3 : 1;
            StoC::EmulatePacket(&pack);
        }
        bool CanInteractWithItem(const GW::Item* item) {
            return item && !IsStorageItem(item) || CanAccessXunlaiChest();
        }
        bool PickUpItem(const Item* item, uint32_t call_target /*= 0*/) {
            auto packet = UI::UIPacket::kInteractAgent{ item->agent_id, call_target == 1 };
            return UI::SendUIMessage(GW::UI::UIMessage::kSendInteractItem, &packet);
        }

        bool DropItem(const Item* item, uint32_t quantity) {
            if (!(DropItem_Func && item))
                return false;
            DropItem_Func(item->item_id, quantity);
            return true;
        }

        bool PingWeaponSet(uint32_t agent_id, uint32_t weapon_item_id, uint32_t offhand_item_id) {
            if (!(PingWeaponSet_Func && agent_id))
                return false;
            PingWeaponSet_Func(agent_id,weapon_item_id,offhand_item_id);
            return true;
        }

        bool EquipItem(const Item* item, uint32_t agent_id) {
            if (!(item && EquipItem_Func))
                return false;
            if (!CanInteractWithItem(item))
                return false;
            if (!agent_id)
                agent_id = Agents::GetControlledCharacterId();
            if (!agent_id)
                return false;
            EquipItem_Func(item->item_id, agent_id);
            return true;
        }

        bool UseItem(const Item* item) {
            if (!(UseItem_Func && item))
                return false;
            if (!CanInteractWithItem(item))
                return false;
            UseItem_Func(item->item_id);
            return true;
        }

        Bag** GetBagArray() {
            auto* i = GetInventory();
            return i ? i->bags : nullptr;
        }

        Bag* GetBag(Constants::Bag bag_id) {
            if (!(bag_id > Constants::Bag::None && bag_id < Constants::Bag::Max))
                return nullptr;
            Bag** bags = GetBagArray();
            const auto bag = bags ? bags[(unsigned)bag_id] : nullptr;
#if _DEBUG
            if (bag)
                GWCA_ASSERT(bag->bag_id() == bag_id);
#endif
            return bag;
        }
        Bag* GetBagByIndex(uint32_t bag_index) {
            return GetBag((Constants::Bag)(bag_index + 1));
        }

        uint32_t GetMaterialStorageStackSize() {
            const auto g = GW::GetGameContext();
            const auto a = g ? g->account : nullptr;
            if (!a) return 250;
            // @Cleanup: Create an AccountMgr.cpp and chuck this stuff in there!
            for (auto& unlock : a->account_unlocked_counts) {
                if (unlock.id == 0x83)
                    return (unlock.unk1 * 250) + 250;
            }
            return 250;

        }

        Item* GetItemBySlot(const Bag* bag, uint32_t slot) {
            if (!bag || slot == 0) return nullptr;
            if (!bag->items.valid()) return nullptr;
            if (slot > bag->items.size()) return nullptr;
            return bag->items[slot - 1];
        }

        Item* GetHoveredItem() {
            const auto tooltip = UI::GetCurrentTooltip();
            if (!tooltip) {
                return nullptr;
            }
            if (tooltip->payload_len == 0x8 && tooltip->payload[1] == 0xff) {
                // Single item hover; { uint32_t item_id, uint32_t 0xff }
                return GetItemById(*(uint32_t*)tooltip->payload);
            }
            if (tooltip->payload_len == 0xC && tooltip->payload[2] == 0xff) {
                // Dual item hover; { uint32_t item_id1, uint32_t item_id2, uint32_t 0xff }
                const auto item_ids = (uint32_t*)tooltip->payload;
                return GetItemById(item_ids[0] ? item_ids[0] : item_ids[1]);
            }
            return nullptr;
        }

        Item* GetItemById(uint32_t item_id) {
            GW::ItemArray* items = item_id ? GetItemArray() : nullptr;
            return items && item_id < items->size() ? items->at(item_id) : nullptr;
        }

        ItemArray* GetItemArray() {
            auto* i = GetItemContext();
            return i && i->item_array.valid() ? &i->item_array : nullptr;
        }
        Inventory* GetInventory() {
            auto* i = GetItemContext();
            return i ? i->inventory : nullptr;
        }

        bool DropGold(uint32_t Amount /*= 1*/) {
            if (!(DropGold_Func && GetGoldAmountOnCharacter() >= Amount))
                return false;
            DropGold_Func(Amount);
            return true;
        }

        bool SalvageSessionCancel() {
            if (!salvage_context)
                return false;
            const auto btn = GW::UI::GetChildFrame(GW::UI::GetFrameById(salvage_context->frame_id), 1);
            return GW::UI::ButtonClick(btn);
        }

        bool DestroyItem(uint32_t item_id) {
            return DestroyItem_Func ? DestroyItem_Func(item_id), true : false;
        }

        bool SalvageMaterials() {
            if (!salvage_context)
                return false;
            const auto prev_context = *salvage_context;
            // Choose materials
            salvage_context->chosen_salvagable = 3;
            // Clear salvagable list to avoid the extra "are you sure" prompt
            salvage_context->salvagable_1 = 0;
            salvage_context->salvagable_2 = 0;
            salvage_context->salvagable_3 = 0;
            // Click "salvage"
            const auto btn = GW::UI::GetChildFrame(GW::UI::GetFrameById(salvage_context->frame_id), 2);
            bool ok = GW::UI::ButtonClick(btn);
            if(salvage_context)
                *salvage_context = prev_context;
            return ok;
            //return SalvageMaterials_Func ? SalvageMaterials_Func(), true : false;
        }

        bool SalvageStart(uint32_t kit_id, uint32_t item_id) {
            if (!(InventorySlot_UICallback_Func && CanInteractWithItem(GetItemById(kit_id))
                && CanInteractWithItem(GetItemById(item_id)))) {
                return false;
            }
            UI::InteractionMessage message = { 0 };
            message.message_id = GW::UI::UIMessage::kMouseClick2;
            uint32_t wparam[4] = { 0 };
            wparam[1] = 1; // Salvage action
            wparam[2] = 6; // Click event
            wparam[3] = kit_id;

            uint32_t uictl_struct[7] = { 0 };
            uictl_struct[6] = item_id; // Fake that the current frame context matches the item we want

            void* wParam_pt = &uictl_struct;
            message.wParam = &wParam_pt;

            InventorySlot_UICallback_Func(&message, wparam, nullptr);
            return true;
        }

        bool IdentifyItem(uint32_t kit_id, uint32_t item_id) {
            if (!(InventorySlot_UICallback_Func && CanInteractWithItem(GetItemById(kit_id))
                && CanInteractWithItem(GetItemById(item_id)))) {
                return false;
            }
            UI::InteractionMessage message = { 0 };
            message.message_id = GW::UI::UIMessage::kMouseClick2;
            uint32_t wparam[4] = { 0 };
            wparam[1] = 2; // Identify action
            wparam[2] = 6; // Click event
            wparam[3] = kit_id;

            uint32_t uictl_struct[7] = { 0 };
            uictl_struct[6] = item_id; // Fake that the current frame context matches the item we want

            void* wParam_pt = &uictl_struct;
            message.wParam = &wParam_pt;

            InventorySlot_UICallback_Func(&message, wparam, nullptr);
            return true;
        }

        uint32_t GetGoldAmountOnCharacter() {
            auto* i = GetInventory();
            return i ? i->gold_character : 0;
        }

        uint32_t GetGoldAmountInStorage() {
            auto* i = GetInventory();
            return i ? i->gold_storage : 0;
        }

        bool ChangeGold(uint32_t character_gold, uint32_t storage_gold) {
            if (!(ChangeGold_Func && (GetGoldAmountInStorage() + GetGoldAmountOnCharacter()) == (character_gold + storage_gold)))
                return false;
            ChangeGold_Func(character_gold, storage_gold);
            return true;
        }

        uint32_t DepositGold(uint32_t amount) {
            uint32_t gold_storage = GetGoldAmountInStorage();
            uint32_t gold_character = GetGoldAmountOnCharacter();
            uint32_t will_move = 0;
            if (amount == 0) {
                will_move = std::min(1000000 - gold_storage, gold_character);
            }
            else {
                if (gold_storage + amount > 1000000)
                    return 0;
                if (amount > gold_character)
                    return 0;
                will_move = amount;
            }
            gold_storage += will_move;
            gold_character -= will_move;
            return ChangeGold(gold_character, gold_storage) ? will_move : 0;
        }

        uint32_t WithdrawGold(uint32_t amount) {
            uint32_t gold_storage = GetGoldAmountInStorage();
            uint32_t gold_character = GetGoldAmountOnCharacter();
            uint32_t will_move = 0;
            if (amount == 0) {
                will_move = std::min(gold_storage, 100000 - gold_character);
            }
            else {
                if (gold_character + amount > 100000)
                    return 0;
                if (amount > gold_storage)
                    return 0;
                will_move = amount;
            }
            gold_storage -= will_move;
            gold_character += will_move;
            return ChangeGold(gold_character, gold_storage) ? will_move : 0;
        }

        bool MoveItem(const Item* from, const Bag* bag, uint32_t slot, uint32_t quantity) {
            if (!(MoveItem_Func && from && bag)) return false;
            if (bag->items.size() < (unsigned)slot) return false;
            if (quantity <= 0) quantity = from->quantity;
            if (quantity > from->quantity) quantity = from->quantity;
            MoveItem_Func(from->item_id, quantity, bag->index, slot);
            return true;
        }

        bool MoveItem(const Item* item, Constants::Bag bag_id, uint32_t slot, uint32_t quantity)
        {
            return MoveItem(item, GetBag(bag_id), slot, quantity);
        }

        bool MoveItem(const Item* from, const Item* to, uint32_t quantity) {
            return MoveItem(from, to->bag, to->slot, quantity);
        }

        bool UseItemByModelId(uint32_t modelid, int bagStart, int bagEnd) {
            return UseItem(GetItemByModelId(modelid, bagStart, bagEnd));
        }

        uint32_t CountItemByModelId(uint32_t modelid, int bagStart, int bagEnd) {
            uint32_t itemcount = 0;
            Bag** bags = GetBagArray();
            Bag* bag = NULL;

            for (int bagIndex = bagStart; bagIndex <= bagEnd; ++bagIndex) {
                bag = bags[bagIndex];
                if (!(bag && bag->items.valid())) continue;
                for (GW::Item* item : bag->items) {
                    if (item && item->model_id == modelid) {
                        itemcount += item->quantity;
                    }
                }
            }

            return itemcount;
        }

        Item* GetItemByModelId(uint32_t modelid, int bagStart, int bagEnd) {
            Bag** bags = GetBagArray();
            Bag* bag = NULL;

            for (int bagIndex = bagStart; bagIndex <= bagEnd; ++bagIndex) {
                bag = bags[bagIndex];
                if (!(bag && bag->items.valid())) continue;
                for (GW::Item* item : bag->items) {
                    if (item && item->model_id == modelid) {
                        return item;
                    }
                }
            }

            return NULL;
        }

        Constants::MaterialSlot GetMaterialSlot(const Item* item) {
            const auto mod = item ? item->GetModifier(9480) : nullptr;
            if(!mod) return Constants::MaterialSlot::Count;
            const auto slot = (Constants::MaterialSlot)mod->arg1();
            if (slot >= Constants::MaterialSlot::BronzeZCoin)
                return Constants::MaterialSlot::Count;
            return slot;
        }
        
        Item* GetItemByModelIdAndModifiers(uint32_t modelid, const ItemModifier* modifiers, uint32_t modifiers_len, int bagStart, int bagEnd) {
            Bag** bags = GetBagArray();
            if (!(bags && modifiers_len && modifiers))
                return nullptr;

            for (int bagIndex = bagStart; bagIndex <= bagEnd; ++bagIndex) {
                const auto bag = bags[bagIndex];
                if (!bag) continue;
                for (const auto item : bag->items) {
                    if (!(item && item->mod_struct_size == modifiers_len && item->model_id == modelid))
                        continue;
                    if (memcmp(item->mod_struct, modifiers, sizeof(*modifiers) * modifiers_len) == 0)
                        return item;
                }
            }

            return nullptr;
        }

        GW::Constants::StoragePane GetStoragePage(void) {
            return (GW::Constants::StoragePane)UI::GetPreference(UI::NumberPreference::StorageBagPage);
        }

        bool GetIsStorageOpen(void) {
            return storage_open_addr && *(uint32_t*)storage_open_addr != 0;
        }

        void RegisterItemClickCallback(
            HookEntry* entry,
            const ItemClickCallback& callback)
        {
            ItemClick_callbacks.insert({ entry, callback });
        }

        void RemoveItemClickCallback(
            HookEntry* entry)
        {
            auto it = ItemClick_callbacks.find(entry);
            if (it != ItemClick_callbacks.end())
                ItemClick_callbacks.erase(it);
        }

        void AsyncGetItemName(const Item* item, std::wstring& res) {
            if (!item) return;
            if (!item || !item->complete_name_enc) return;
            wchar_t* str = item->complete_name_enc;
            UI::AsyncDecodeStr(str, &res);
        }

        uint32_t GetEquipmentVisibilityState() {
            auto* w = GetWorldContext();
            return w ? w->equipment_status : 0;
        }
        EquipmentStatus GetEquipmentVisibility(EquipmentType type) {
            return (EquipmentStatus)((GetEquipmentVisibilityState() >> (uint32_t)type) & 0x3);
        }
        bool SetEquipmentVisibility(EquipmentType type, EquipmentStatus state) {
            if (GetEquipmentVisibility(type) == state)
                return true;
            if (!ChangeEquipmentVisibility_Func)
                return false;
            ChangeEquipmentVisibility_Func((uint32_t)((uint32_t)state << (uint32_t)type), (uint32_t)(0x3 << (uint32_t)type));
            return true;
        }

        const PvPItemUpgradeInfo* GetPvPItemUpgrade(uint32_t pvp_item_upgrade_idx)
        {
            const auto& arr = GetPvPItemUpgradesArray();
            if (pvp_item_upgrade_idx < arr.size()) {
                return &arr[pvp_item_upgrade_idx];
            }
            return nullptr;
        }
        const Array<PvPItemUpgradeInfo>& GetPvPItemUpgradesArray()
        {
            return unlocked_pvp_item_upgrade_array;
        }
        const PvPItemInfo* GetPvPItemInfo(uint32_t pvp_item_idx)
        {
            const auto& arr = GetPvPItemInfoArray();
            if (pvp_item_idx < arr.size()) {
                return &arr[pvp_item_idx];
            }
            return nullptr;
        }
        const Array<CompositeModelInfo>& GetCompositeModelInfoArray()
        {
            return *composite_model_info_array;
        }
        const CompositeModelInfo* GetCompositeModelInfo(uint32_t model_file_id)
        {
            const auto& arr = GetCompositeModelInfoArray();
            if (model_file_id < arr.size()) {
                return &arr[model_file_id];
            }
            return nullptr;
        }
        const Array<PvPItemInfo>& GetPvPItemInfoArray()
        {
            return pvp_item_array;
        }

        bool GetPvPItemUpgradeEncodedName(uint32_t pvp_item_upgrade_idx, wchar_t** out)
        {
            const auto info = GetPvPItemUpgrade(pvp_item_upgrade_idx);
            if (!(info && GetPvPItemUpgradeInfoName_Func && out))
                return false;
            *out = nullptr;
            wchar_t* tmp;
            GetPvPItemUpgradeInfoName_Func(pvp_item_upgrade_idx, false, out, &tmp);
            return *out != nullptr;
        }
        bool GetPvPItemUpgradeEncodedDescription(uint32_t pvp_item_upgrade_idx, wchar_t** out)
        {
            const auto info = GetPvPItemUpgrade(pvp_item_upgrade_idx);
            if (!(info && GetPvPItemUpgradeInfoName_Func && out))
                return false;
            *out = nullptr;
            wchar_t* tmp;
            GetPvPItemUpgradeInfoName_Func(pvp_item_upgrade_idx, false, &tmp, out);
            return *out != nullptr;
        }

        const ItemFormula* GetItemFormula(const GW::Item* item) {
            if (!(item && item_formulas && item->item_formula < item_formula_count))
                return nullptr;
            return &item_formulas[item->item_formula];
        }
    }

} // namespace GW
