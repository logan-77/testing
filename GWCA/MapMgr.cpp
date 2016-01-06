#include "MapMgr.h"

#include "CtoSMgr.h"

void GWCA::MapMgr::Travel(GwConstants::MapID MapID,
	int District /*= 0*/, int Region /*= 0*/, int Language /*= 0*/) {

	static PAB_ZoneMap* pak = new PAB_ZoneMap();

	pak->mapid = static_cast<DWORD>(MapID);
	pak->district = District;
	pak->region = Region;
	pak->language = Language;
	pak->unk = 0;

	CtoSMgr::Instance().SendPacket<PAB_ZoneMap>(pak);
}

void GWCA::MapMgr::Travel(GwConstants::MapID MapID, GwConstants::District district, int district_number) {
	switch (district) {
	case GwConstants::District::Current:
		Travel(MapID, district_number, GetRegion(), GetLanguage());
		break;
	case GwConstants::District::International:
		Travel(MapID, district_number, GwConstants::Region::International, 0);
		break;
	case GwConstants::District::American:
		Travel(MapID, district_number, GwConstants::Region::America, 0);
		break;
	case GwConstants::District::EuropeEnglish:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::English);
		break;
	case GwConstants::District::EuropeFrench:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::French);
		break;
	case GwConstants::District::EuropeGerman:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::German);
		break;
	case GwConstants::District::EuropeItalian:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::Italian);
		break;
	case GwConstants::District::EuropeSpanish:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::Spanish);
		break;
	case GwConstants::District::EuropePolish:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::Polish);
		break;
	case GwConstants::District::EuropeRussian:
		Travel(MapID, district_number, GwConstants::Region::Europe, GwConstants::EuropeLanguage::Russian);
		break;
	case GwConstants::District::AsiaKorean:
		Travel(MapID, district_number, GwConstants::Region::Korea, 0);
		break;
	case GwConstants::District::AsiaChinese:
		Travel(MapID, district_number, GwConstants::Region::China, 0);
		break;
	case GwConstants::District::AsiaJapanese:
		Travel(MapID, district_number, GwConstants::Region::Japan, 0);
		break;
	}
}

DWORD GWCA::MapMgr::GetInstanceTime() {
	return *MemoryMgr::ReadPtrChain<DWORD*>(MemoryMgr::GetContextPtr(), 2, 0x8, 0x1AC);
}

GwConstants::MapID GWCA::MapMgr::GetMapID() {
	return static_cast<GwConstants::MapID>(*(DWORD*)MemoryMgr::MapIDPtr);
}

GwConstants::InstanceType GWCA::MapMgr::GetInstanceType() {
	return *(GwConstants::InstanceType*)(MemoryMgr::agArrayPtr - 0xF0);
}

GWCA::GW::MissionMapIconArray GWCA::MapMgr::GetMissionMapIconArray() {
	return *MemoryMgr::ReadPtrChain<GW::MissionMapIconArray*>(MemoryMgr::GetContextPtr(), 2, 0x2C, 0x7EC);
}

GWCA::GW::PathingMapArray GWCA::MapMgr::GetPathingMap() {
	return *MemoryMgr::ReadPtrChain<GW::PathingMapArray*>(MemoryMgr::GetContextPtr(), 4, 0x14, 0x74, 0x0, 0x18);
}
