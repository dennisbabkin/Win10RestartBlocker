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
#include "CDropTarget32.h"



CDropTarget32::CDropTarget32(DRAG_N_DROP_FLAGS flgs) :
	m_lRefCount(1)
	, _flags(flgs)
	, _allowedDropType(DIT_UNKNOWN)
	, _pDnDReg(NULL)
	, _bComInitted(SUCCEEDED(::OleInitialize(NULL)))
{
	//Constructor

}

CDropTarget32::~CDropTarget32()
{
	//Destructor

	//Make sure that the user released the drag-and-drop objects!
	assert(!_pDnDReg);		//Make sure to call UnregisterFromDragAndDrop()!

	if (_bComInitted)
	{
		//Uninit OLE
		::OleUninitialize();
	}
}


HRESULT __stdcall CDropTarget32::QueryInterface(REFIID iid, void** ppvObject)
{
	//IUnknown::QueryInterface
	if (iid == IID_IDropTarget || iid == IID_IUnknown)
	{
		AddRef();
		*ppvObject = this;
		return S_OK;
	}
	else
	{
		*ppvObject = 0;
		return E_NOINTERFACE;
	}
}

ULONG __stdcall CDropTarget32::AddRef(void)
{
	//IUnknown::AddRef
	return InterlockedIncrement(&m_lRefCount);
}

ULONG __stdcall CDropTarget32::Release(void)
{
	//IUnknown::Release
	LONG count = InterlockedDecrement(&m_lRefCount);

	if (count == 0)
	{
		delete this;
		return 0;
	}
	else
	{
		return count;
	}
}

HRESULT __stdcall CDropTarget32::DragEnter(IDataObject* pDataObject, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect)
{
	//IDropTarget::DragEnter
	_allowedDropType = queryDataObject(pDataObject);

	if (_allowedDropType != DIT_UNKNOWN)
	{
		//Get the dropeffect based on keyboard state
		*pdwEffect = dropEffect(grfKeyState, pt, *pdwEffect);

		//Ask caller to process it
		BOOL bSetFocus = TRUE;
		OnDragAndDrop_Began(_allowedDropType, _pDnDReg, &bSetFocus, grfKeyState, pt, pdwEffect);

		if (bSetFocus)
		{
			//Set focus to the window
			assert(_pDnDReg->hWndTarget);

			if (_pDnDReg->type == DND_WND_T_GENERIC)
				::SetForegroundWindow(_pDnDReg->hWndTarget);

			::SetFocus(_pDnDReg->hWndTarget);
		}
	}
	else
	{
		*pdwEffect = DROPEFFECT_NONE;
	}

	return S_OK;
}

HRESULT __stdcall CDropTarget32::DragOver(DWORD grfKeyState, POINTL pt, DWORD* pdwEffect)
{
	//IDropTarget::DragOver
	if (_allowedDropType != DIT_UNKNOWN)
	{
		*pdwEffect = dropEffect(grfKeyState, pt, *pdwEffect);

		//Ask caller to process it
		OnDragAndDrop_Pending(_allowedDropType, _pDnDReg, grfKeyState, pt, pdwEffect);

	}
	else
	{
		*pdwEffect = DROPEFFECT_NONE;
	}

	return S_OK;
}

HRESULT __stdcall CDropTarget32::DragLeave(void)
{
	//IDropTarget::DragLeave
	if (_allowedDropType != DIT_UNKNOWN)
	{
		//Ask caller to process it
		OnDragAndDrop_Ended(_allowedDropType, _pDnDReg);

		_allowedDropType = DIT_UNKNOWN;
	}

	return S_OK;
}

HRESULT __stdcall CDropTarget32::Drop(IDataObject* pDataObject, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect)
{
	//IDropTarget::Drop

	if (_allowedDropType != DIT_UNKNOWN)
	{
		*pdwEffect = dropEffect(grfKeyState, pt, *pdwEffect);

		//Get data that was dropped
		DRAGGED_ITEMS items;
		DRAG_ITEM_TYPE dataType = getDroppedData(pDataObject, &items);
		
		DRAG_N_DROP_DROP_FLAGS dropFlags = DND_DRP_FLG_None;

		//See if it's a touch screen
		LPARAM lExtra = ::GetMessageExtraInfo();
#define MOUSEEVENTF_FROMTOUCH 0xFF515700
		if ((lExtra & MOUSEEVENTF_FROMTOUCH) == MOUSEEVENTF_FROMTOUCH)
			(UINT&)dropFlags |= DND_DRP_FLG_TOUCH_SCREEN;

		//Ask caller to process it
		if (!OnDragAndDrop_DropData(dataType, _pDnDReg, &items, grfKeyState, pt, pdwEffect, dropFlags))
		{
			//Failed
			*pdwEffect = DROPEFFECT_NONE;

			::MessageBeep(MB_ICONERROR);
		}

	}
	else
	{
		*pdwEffect = DROPEFFECT_NONE;
	}

	return S_OK;
}


BOOL CDropTarget32::RegisterForDragAndDrop(DRAG_N_DROP_REGISTER* pInfo)
{
	//Register window to accept drag-and-drop
	//INFO: Make sure to call UnregisterFromDragAndDrop() before window is destroyed!
	//'pInfo' = details - must be provided
	//RETURN:
	//		= TRUE if success
	//		= FALSE if failed (check GetLastError() for info)
	assert(pInfo);
	BOOL bRes = FALSE;
	int nOSError = 0;

	if (pInfo &&
		pInfo->hWndTarget &&
		pInfo->type != DND_WND_T_Unknown)
	{
		HRESULT hr;

		//Only if not registered already
		if (!_pDnDReg)
		{
			//Copy parameters
			DRAG_N_DROP_REGISTER* pDNDR = new (std::nothrow) DRAG_N_DROP_REGISTER(*pInfo);
			if (pDNDR)
			{
				//Acquire a lock
				if (SUCCEEDED(hr = ::CoLockObjectExternal(this, TRUE, FALSE)))
				{
					//Register window
					if (SUCCEEDED(hr = ::RegisterDragDrop(pInfo->hWndTarget, this)))
					{
						//Done
						_pDnDReg = pDNDR;

						bRes = TRUE;
					}
					else
					{
						//Failed
						nOSError = (int)hr;

						hr = ::CoLockObjectExternal(this, FALSE, TRUE);
						assert(SUCCEEDED(hr));

						delete pDNDR;
						pDNDR = NULL;
					}
				}
				else
				{
					//Error
					nOSError = (int)hr;

					delete pDNDR;
					pDNDR = NULL;
				}
			}
			else
				nOSError = ERROR_OUTOFMEMORY;
		}
		else
			nOSError = ERROR_ALREADY_ASSIGNED;
	}
	else
		nOSError = ERROR_EMPTY;

	::SetLastError(nOSError);
	return bRes;
}


BOOL CDropTarget32::UnregisterFromDragAndDrop()
{
	//Remove previously registered window from accepting drag-and-drop
	//RETURN:
	//		= TRUE if no errors
	//		= FALSE if failed (check GetLastError() for info)
	BOOL bRes = TRUE;
	int nOSError = 0;

	if (!_pDnDReg)
	{
		//Nothing is registered
		return bRes;
	}

	//Unregister drag-and-drop
	assert(_pDnDReg->hWndTarget);
	HRESULT hr = ::RevokeDragDrop(_pDnDReg->hWndTarget);
	if (FAILED(hr))
	{
		nOSError = (int)hr;
		assert(NULL);
		bRes = FALSE;
	}

	//Unlock the object
	hr = ::CoLockObjectExternal(this, FALSE, TRUE);
	assert(SUCCEEDED(hr));

	//Free mem
	delete _pDnDReg;
	_pDnDReg = NULL;

	::SetLastError(nOSError);
	return bRes;
}


DRAG_ITEM_TYPE CDropTarget32::queryDataObject(IDataObject* pDataObject)
{
	//Determine the type of the drag-and-dropped data in 'pDataObject'
	//RETURN:
	//		= Type of data if it is supported, or
	//		= DIT_UNKNOWN if it is not
	assert(_pDnDReg);

	DRAG_ITEM_TYPE dit = getDroppedData(pDataObject);
	if (dit != DIT_UNKNOWN)
	{
		//Ask the caller if it's OK to accept this object
		if (!OnDragAndDrop_IsAllowed(dit, _pDnDReg))
		{
			//Caller refused
			dit = DIT_UNKNOWN;
		}
	}

	return dit;
}

DRAG_ITEM_TYPE CDropTarget32::getDroppedData(IDataObject* pDataObject, DRAGGED_ITEMS* pOutData)
{
	//Determine the type of an object in 'pDataObject'
	//'pOutData' = if not NULL, receives the data interpreted from 'pDataObject', only if results is not DIT_UNKNOWN
	//RETURN:
	//		= Object type
	//		= DIT_UNKNOWN if failed - check GetLastError() for info
	DRAG_ITEM_TYPE res = DIT_UNKNOWN;
	int nOSError = 0;

	__try
	{
		res = _getDroppedData_raw(pDataObject, pOutData, nOSError);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//Catch all exceptions
		nOSError = 1064;
		res = DIT_UNKNOWN;
		assert(NULL);
	}

	::SetLastError(nOSError);
	return res;
}

DRAG_ITEM_TYPE CDropTarget32::_getDroppedData_raw(IDataObject* pDataObject, DRAGGED_ITEMS* pOutData, int& nOSError)
{
	assert(pDataObject);
	assert(_pDnDReg);
	assert(_pDnDReg->hWndTarget);
	DRAG_ITEM_TYPE res = DIT_UNKNOWN;

	//Only if our window is enabled
	if (::IsWindowEnabled(_pDnDReg->hWndTarget))
	{
		// http://msdn.microsoft.com/en-us/library/windows/desktop/ff729168(v=vs.85).aspx
		static FORMATETC fmtetc_file = { CF_HDROP, 0, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
		static FORMATETC fmtetc_txt = { CF_UNICODETEXT, 0, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };

		HRESULT hr;
		STGMEDIUM stgmed;

		//See if our data type
		hr = pDataObject->QueryGetData(&fmtetc_file);
		if (hr == S_OK)
		{
			//URIs
			if (pOutData)
			{
				if ((hr = pDataObject->GetData(&fmtetc_file, &stgmed)) == S_OK)
				{
					if (stgmed.tymed == TYMED_HGLOBAL)
					{
						HDROP hDrop = (HDROP)stgmed.hGlobal;

						//See how many files
						int nmFiles = ::DragQueryFile(hDrop, (UINT)0xFFFFFFFF, NULL, 0);

						//We're inrterested if more than one file too
						if (nmFiles > 0)
						{
							//Assume success
							res = DIT_URI;

							pOutData->Clear(res);
							std::wstring str;

							//Start collecting data
							for (int i = 0; i < nmFiles; i++)
							{
								//Get required file path size
								int nLnPath = ::DragQueryFile(hDrop, i, NULL, 0);
								if (nLnPath > 0)
								{
									str.resize(nLnPath);

									if (::DragQueryFile(hDrop, i, &str[0], nLnPath + 1) == nLnPath)
									{
										if (!str.empty())
										{
											//Add to array
											pOutData->arrPaths.push_back(str);
										}
									}
									else
									{
										//Failed
										nOSError = 24;
										assert(NULL);
										res = DIT_UNKNOWN;
										break;
									}
								}
								else
								{
									//Failed
									nOSError = 4306;
									assert(NULL);
									res = DIT_UNKNOWN;
									break;
								}
							}

						}
						else
							nOSError = 2115;
					}
					else
						nOSError = 15117;

					//Release object
					ReleaseStgMedium(&stgmed);
				}
				else
					nOSError = (int)hr;
			}
			else
			{
				//Only checking
				res = DIT_URI;
			}
		}
		else if ((hr = pDataObject->QueryGetData(&fmtetc_txt)) == S_OK)
		{
			//Text
			if (pOutData)
			{
				if ((hr = pDataObject->GetData(&fmtetc_txt, &stgmed)) == S_OK)
				{
					if (stgmed.tymed == TYMED_HGLOBAL)
					{
						//Lock the HGLOBAL block
						PVOID pData = ::GlobalLock(stgmed.hGlobal);
						if (pData)
						{
							intptr_t szcbData = ::GlobalSize(stgmed.hGlobal);
							if (szcbData > 0)
							{
								if ((szcbData % sizeof(WCHAR)) == 0)
								{
									//Success;
									res = DIT_TEXT;

									pOutData->Clear(res);

									pOutData->strText.assign((const WCHAR*)pData, szcbData / sizeof(WCHAR));
								}
								else
									nOSError = 3756;
							}
							else
								nOSError = ::GetLastError();

							//Unlock memory
							::GlobalUnlock(stgmed.hGlobal);
						}
						else
							nOSError = ::GetLastError();
					}
					else
						nOSError = 15117;

					//Release object
					ReleaseStgMedium(&stgmed);
				}
				else
					nOSError = (int)hr;
			}
			else
			{
				//Only checking
				res = DIT_TEXT;
			}
		}
		else
			nOSError = 15112;
	}
	else
		nOSError = 1400;

	return res;
}


DWORD CDropTarget32::dropEffect(DWORD grfKeyState, POINTL pt, DWORD dwAllowed)
{
	//Determines type of operation for dragging
	DWORD dwEffect = 0;

	//Determine type
	DWORD nDrgTypeMove = _allowedDropType == DIT_URI ? DROPEFFECT_LINK : ((_flags & DND_FLG_ALLOW_MOVE) ? DROPEFFECT_MOVE : DROPEFFECT_COPY);
	DWORD nDrgTypeCopy = _allowedDropType == DIT_URI ? DROPEFFECT_LINK : DROPEFFECT_COPY;

	//See if any keys pressed
	DWORD dwAuxKeys = grfKeyState & (MK_CONTROL | MK_SHIFT);
	if (dwAuxKeys & MK_CONTROL)
	{
		dwEffect = dwAllowed & nDrgTypeCopy;
	}
	else if (dwAuxKeys & MK_SHIFT)
	{
		dwEffect = dwAllowed & nDrgTypeMove;
	}

	//If no effect, use the one from dropsource
	if (dwEffect == 0)
	{
		if (dwAllowed & DROPEFFECT_COPY)
			dwEffect = nDrgTypeCopy;
		if (dwAllowed & DROPEFFECT_MOVE)
			dwEffect = nDrgTypeMove;
		if (dwAllowed & DROPEFFECT_LINK)
			dwEffect = DROPEFFECT_LINK;
	}

	return dwEffect;
}

