//  
//    Windows 10 Update Restart Blocker
//    "Control forced restarts from Windows Updates & custom patch for its vulnerability bug."
//    Copyright (c) 2021 www.dennisbabkin.com
//    
//        https://dennisbabkin.com/w10urb
//    
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        https://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//  
//


//Class that implements drag-and-drop operations for a window
#pragma once

#include <oleidl.h>
#include <assert.h>
#include <new>
#include <vector>
#include <string>


enum DRAG_N_DROP_FLAGS {
	DND_FLG_None = 0,

	DND_FLG_ALLOW_MOVE = 0x1,		//Set to allow "move" actions (or reset to use "copy" instead)
};


enum DRAG_N_DROP_WND_TYPE {
	DND_WND_T_Unknown,

	DND_WND_T_GENERIC,				//Generic window for drag-and-drop
};

struct DRAG_N_DROP_REGISTER {
	HWND hWndTarget;				//Window that will receive drag-and-drops
	DRAG_N_DROP_WND_TYPE type;		//Type of window in 'hWndTarget'

	DRAG_N_DROP_REGISTER(HWND hWnd = NULL, DRAG_N_DROP_WND_TYPE wndType = DND_WND_T_Unknown)
		: hWndTarget(hWnd)
		, type(wndType)
	{
	}
};


enum DRAG_ITEM_TYPE {
	DIT_UNKNOWN,
	DIT_URI,			//Dragged item is a path (or multiple-paths)
	DIT_TEXT,			//Dragged item is a Unicode text
};

struct DRAGGED_ITEMS {
	DRAG_ITEM_TYPE dataType;					//Type of data
	std::wstring strText;						//Used only if 'dataType' == DIT_TEXT
	std::vector<std::wstring> arrPaths;			//Used only if 'dataType' == DIT_URI

	DRAGGED_ITEMS()
		: dataType(DIT_UNKNOWN)
	{
	}

	void Clear(DRAG_ITEM_TYPE type = DIT_UNKNOWN)
	{
		//Clear all data
		dataType = type;
		strText.clear();
		arrPaths.clear();
	}
};

enum DRAG_N_DROP_DROP_FLAGS {
	DND_DRP_FLG_None = 0x0,

	DND_DRP_FLG_TOUCH_SCREEN = 0x1,			//TRUE if drag-and-drop was generated on a touch screen device
};








class CDropTarget32 : public IDropTarget
{
public:
	CDropTarget32(DRAG_N_DROP_FLAGS flgs = DND_FLG_None);
	~CDropTarget32();

	BOOL RegisterForDragAndDrop(DRAG_N_DROP_REGISTER* pInfo);
	BOOL UnregisterFromDragAndDrop();

	//Notification functions that must be implemented by the caller:
	virtual BOOL OnDragAndDrop_IsAllowed(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo) = 0;
	virtual void OnDragAndDrop_Began(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, BOOL* pbSetFocus, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect) = 0;
	virtual void OnDragAndDrop_Pending(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect) = 0;
	virtual void OnDragAndDrop_Ended(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo) = 0;
	virtual BOOL OnDragAndDrop_DropData(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, DRAGGED_ITEMS* pDroppedItems, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect, DRAG_N_DROP_DROP_FLAGS dropFlags) = 0;

private:
	//IUnknown implementation
	HRESULT __stdcall QueryInterface(REFIID iid, void** ppvObject);
	ULONG	__stdcall AddRef(void);
	ULONG	__stdcall Release(void);

	//IDropTarget implementation
	HRESULT __stdcall DragEnter(IDataObject* pDataObject, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect);
	HRESULT __stdcall DragOver(DWORD grfKeyState, POINTL pt, DWORD * pdwEffect);
	HRESULT __stdcall DragLeave(void);
	HRESULT __stdcall Drop(IDataObject* pDataObject, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect);

	LONG m_lRefCount;
	BOOL _bComInitted;

	DRAG_N_DROP_FLAGS _flags;
	DRAG_N_DROP_REGISTER* _pDnDReg;			//NULL if not registered yet. Otherwise drop-target info
	DRAG_ITEM_TYPE _allowedDropType;		//Type of allowed drop, or DIT_UNKNOWN if not allowed


	DRAG_ITEM_TYPE queryDataObject(IDataObject * pDataObject);
	DRAG_ITEM_TYPE getDroppedData(IDataObject * pDataObject, DRAGGED_ITEMS * pOutData = NULL);
	DRAG_ITEM_TYPE _getDroppedData_raw(IDataObject * pDataObject, DRAGGED_ITEMS * pOutData, int& nOSError);
	DWORD dropEffect(DWORD grfKeyState, POINTL pt, DWORD dwAllowed);
};

