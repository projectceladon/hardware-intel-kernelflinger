/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <efi.h>
#include <efilib.h>
#include <lib.h>
#include "protocol.h"
#include "uefi_utils.h"

extern EFI_GUID GraphicsOutputProtocol;

typedef struct {
	UINT8   Blue;
	UINT8   Green;
	UINT8   Red;
	UINT8   Reserved;
} BMP_COLOR_MAP;

typedef struct {
	CHAR8         CharB;
	CHAR8         CharM;
	UINT32        Size;
	UINT16        Reserved[2];
	UINT32        ImageOffset;
	UINT32        HeaderSize;
	UINT32        PixelWidth;
	UINT32        PixelHeight;
	UINT16        Planes;       // Must be 1
	UINT16        BitPerPixel;  // 1, 4, 8, or 24
	UINT32        CompressionType;
	UINT32        ImageSize;    // Compressed image size in bytes
	UINT32        XPixelsPerMeter;
	UINT32        YPixelsPerMeter;
	UINT32        NumberOfColors;
	UINT32        ImportantColors;
} __attribute((packed)) BMP_IMAGE_HEADER;

EFI_STATUS ConvertBmpToGopBlt (VOID *BmpImage, UINTN BmpImageSize,
			       VOID **GopBlt, UINTN *GopBltSize,
			       UINTN *PixelHeight, UINTN *PixelWidth)
{
	UINT8                         *Image;
	UINT8                         *ImageHeader;
	BMP_IMAGE_HEADER              *BmpHeader;
	BMP_COLOR_MAP                 *BmpColorMap;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Blt;
	UINT64                        BltBufferSize;
	UINTN                         Index;
	UINTN                         Height;
	UINTN                         Width;
	UINTN                         ImageIndex;
	UINT32                        DataSizePerLine;
	BOOLEAN                       IsAllocated;
	UINT32                        ColorMapNum;



	if (sizeof (BMP_IMAGE_HEADER) > BmpImageSize) {
		return EFI_INVALID_PARAMETER;
	}

	BmpHeader = (BMP_IMAGE_HEADER *) BmpImage;

	if (BmpHeader->CharB != 'B' || BmpHeader->CharM != 'M') {
		return EFI_UNSUPPORTED;
	}

	//
	// Doesn't support compress.
	//
	if (BmpHeader->CompressionType != 0) {
		return EFI_UNSUPPORTED;
	}

	//
	// Only support BITMAPINFOHEADER format.
	// BITMAPFILEHEADER + BITMAPINFOHEADER = BMP_IMAGE_HEADER
	//
	if (BmpHeader->HeaderSize != sizeof (BMP_IMAGE_HEADER) - offsetof(BMP_IMAGE_HEADER, HeaderSize))
		return EFI_UNSUPPORTED;

	//
	// The data size in each line must be 4 byte alignment.
	//
	DataSizePerLine = ((BmpHeader->PixelWidth * BmpHeader->BitPerPixel + 31) >> 3) & (~0x3);
	BltBufferSize = MultU64x32 (DataSizePerLine, BmpHeader->PixelHeight);
	if (BltBufferSize > (UINT32) ~0) {
		return EFI_INVALID_PARAMETER;
	}

	if ((BmpHeader->Size != BmpImageSize) ||
	    (BmpHeader->Size < BmpHeader->ImageOffset) ||
	    (BmpHeader->Size - BmpHeader->ImageOffset !=  BmpHeader->PixelHeight * DataSizePerLine)) {
		return EFI_INVALID_PARAMETER;
	}

	//
	// Calculate Color Map offset in the image.
	//
	Image       = BmpImage;
	BmpColorMap = (BMP_COLOR_MAP *) (Image + sizeof (BMP_IMAGE_HEADER));
	if (BmpHeader->ImageOffset < sizeof (BMP_IMAGE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	if (BmpHeader->ImageOffset > sizeof (BMP_IMAGE_HEADER)) {
		switch (BmpHeader->BitPerPixel) {
		case 1:
			ColorMapNum = 2;
			break;
		case 4:
			ColorMapNum = 16;
			break;
		case 8:
			ColorMapNum = 256;
			break;
		default:
			ColorMapNum = 0;
			break;
		}
		if (BmpHeader->ImageOffset - sizeof (BMP_IMAGE_HEADER) != sizeof (BMP_COLOR_MAP) * ColorMapNum) {
			return EFI_INVALID_PARAMETER;
		}
	}

	//
	// Calculate graphics image data address in the image
	//
	Image         = ((UINT8 *) BmpImage) + BmpHeader->ImageOffset;
	ImageHeader   = Image;

	//
	// Calculate the BltBuffer needed size.
	//
	BltBufferSize = MultU64x32 ((UINT64) BmpHeader->PixelWidth, BmpHeader->PixelHeight);
	//
	// Ensure the BltBufferSize * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) doesn't overflow
	//
	if (BltBufferSize > DivU64x32 ((UINTN) ~0, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL), NULL)) {
		return EFI_UNSUPPORTED;
	}
	BltBufferSize = MultU64x32 (BltBufferSize, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));

	IsAllocated   = FALSE;
	if (*GopBlt == NULL) {
		//
		// GopBlt is not allocated by caller.
		//
		*GopBltSize = (UINTN) BltBufferSize;
		*GopBlt     = AllocatePool (*GopBltSize);
		IsAllocated = TRUE;
		if (*GopBlt == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}
	} else {
		//
		// GopBlt has been allocated by caller.
		//
		if (*GopBltSize < (UINTN) BltBufferSize) {
			*GopBltSize = (UINTN) BltBufferSize;
			return EFI_BUFFER_TOO_SMALL;
		}
	}

	*PixelWidth   = BmpHeader->PixelWidth;
	*PixelHeight  = BmpHeader->PixelHeight;

	//
	// Convert image from BMP to Blt buffer format
	//
	BltBuffer = *GopBlt;
	for (Height = 0; Height < BmpHeader->PixelHeight; Height++) {
		Blt = &BltBuffer[(BmpHeader->PixelHeight - Height - 1) * BmpHeader->PixelWidth];
		for (Width = 0; Width < BmpHeader->PixelWidth; Width++, Image++, Blt++) {
			switch (BmpHeader->BitPerPixel) {
			case 1:
				//
				// Convert 1-bit (2 colors) BMP to 24-bit color
				//
				for (Index = 0; Index < 8 && Width < BmpHeader->PixelWidth; Index++) {
					Blt->Red    = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Red;
					Blt->Green  = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Green;
					Blt->Blue   = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Blue;
					Blt++;
					Width++;
				}

				Blt--;
				Width--;
				break;

			case 4:
				//
				// Convert 4-bit (16 colors) BMP Palette to 24-bit color
				//
				Index       = (*Image) >> 4;
				Blt->Red    = BmpColorMap[Index].Red;
				Blt->Green  = BmpColorMap[Index].Green;
				Blt->Blue   = BmpColorMap[Index].Blue;
				if (Width < (BmpHeader->PixelWidth - 1)) {
					Blt++;
					Width++;
					Index       = (*Image) & 0x0f;
					Blt->Red    = BmpColorMap[Index].Red;
					Blt->Green  = BmpColorMap[Index].Green;
					Blt->Blue   = BmpColorMap[Index].Blue;
				}
				break;

			case 8:
				//
				// Convert 8-bit (256 colors) BMP Palette to 24-bit color
				//
				Blt->Red    = BmpColorMap[*Image].Red;
				Blt->Green  = BmpColorMap[*Image].Green;
				Blt->Blue   = BmpColorMap[*Image].Blue;
				break;

			case 24:
				//
				// It is 24-bit BMP.
				//
				Blt->Blue   = *Image++;
				Blt->Green  = *Image++;
				Blt->Red    = *Image;
				break;

			default:
				//
				// Other bit format BMP is not supported.
				//
				if (IsAllocated) {
					FreePool (*GopBlt);
					*GopBlt = NULL;
				}
				return EFI_UNSUPPORTED;
				break;
			};

		}

		ImageIndex = (UINTN) (Image - ImageHeader);
		if ((ImageIndex % 4) != 0) {
			//
			// Bmp Image starts each row on a 32-bit boundary!
			//
			Image = Image + (4 - (ImageIndex % 4));
		}
	}

	return EFI_SUCCESS;
}

EFI_STATUS find_device_partition(const EFI_GUID *guid, EFI_HANDLE **handles, UINTN *no_handles)
{
	EFI_STATUS ret;
	*handles = NULL;

	ret = LibLocateHandleByDiskSignature(
		MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
		SIGNATURE_TYPE_GUID,
		(void *)guid,
		no_handles,
		handles);
	if (EFI_ERROR(ret) || *no_handles == 0)
		error(L"Failed to found partition %g\n", guid);
	return ret;
}

EFI_STATUS get_esp_handle(EFI_HANDLE *esp)
{
	EFI_STATUS ret;
	UINTN no_handles;
	EFI_HANDLE *handles;

	ret = find_device_partition(&EfiPartTypeSystemPartitionGuid, &handles, &no_handles);
	if (EFI_ERROR(ret)) {
		error(L"Failed to found partition: %r\n", ret);
		goto out;
	}

	if (no_handles == 0) {
		error(L"Can't find loader partition!\n");
		ret = EFI_NOT_FOUND;
		goto out;
	}
	if (no_handles > 1) {
		error(L"Multiple loader partition found!\n");
		goto free_handles;
	}
	*esp = handles[0];
	return EFI_SUCCESS;

free_handles:
	if (handles)
		FreePool(handles);
out:
	return ret;
}

EFI_STATUS get_esp_fs(EFI_FILE_IO_INTERFACE **esp_fs)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_GUID SimpleFileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_HANDLE esp_handle = NULL;
	EFI_FILE_IO_INTERFACE *esp;

	ret = get_esp_handle(&esp_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to get ESP partition: %r\n", ret);
		return ret;
	}

	ret = handle_protocol(esp_handle, &SimpleFileSystemProtocol,
			      (void **)&esp);
	if (EFI_ERROR(ret)) {
		error(L"HandleProtocol", ret);
		return ret;
	}

	*esp_fs = esp;

	return ret;
}

EFI_STATUS uefi_read_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void **data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE_INFO *info;
	UINTN info_size;
	EFI_FILE *file;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &file);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Open, 5, file, &file, filename, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(ret))
		goto out;

	info_size = SIZE_OF_EFI_FILE_INFO + 200;

	info = AllocatePool(info_size);
	if (!info)
		goto close;

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &info_size, info);
	if (EFI_ERROR(ret))
		goto free_info;

	*size = info->FileSize;
	*data = AllocatePool(*size);

retry:
	ret = uefi_call_wrapper(file->Read, 3, file, size, *data);
	if (ret == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(*size);
		goto retry;
	}

	if (EFI_ERROR(ret))
		FreePool(*data);

free_info:
	FreePool(info);
close:
	uefi_call_wrapper(file->Close, 1, file);
out:
	if (EFI_ERROR(ret))
		error(L"Failed to read file %s:%r\n", filename, ret);
	return ret;
}

EFI_STATUS gop_display_blt(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Blt, UINTN height, UINTN width)
{
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL pix = {0x00, 0x00, 0x00, 0x00};
	EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
	UINTN hres, vres = 0;
	UINTN posx, posy = 0;
	EFI_STATUS ret;

	ret = LibLocateProtocol(&GraphicsOutputProtocol, (void **)&gop);
 	if (EFI_ERROR(ret) || !gop)
		goto out;

	hres = gop->Mode->Info->HorizontalResolution;
	vres = gop->Mode->Info->VerticalResolution;
	posx = (hres/2) - (width/2);
	posy = (vres/2) - (height/2);

	ret = uefi_call_wrapper(gop->Blt, 10, gop, &pix, EfiBltVideoFill, 0, 0, 0, 0, hres, vres, 0);
 	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(gop->Blt, 10, gop, Blt, EfiBltBufferToVideo, 0, 0, posx, posy, width, height, 0);

out:
	if (EFI_ERROR(ret))
		error(L"Failed to display blt\n");
	return ret;
}

EFI_STATUS uefi_write_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	if (EFI_ERROR(ret))
		error(L"Failed to write file %s:%r\n", filename, ret);
	return ret;
}

EFI_STATUS uefi_create_dir(EFI_FILE *parent, EFI_FILE **dir, CHAR16 *dirname)
{
	return uefi_call_wrapper(parent->Open, 5, parent, dir, dirname,
				 EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
				 EFI_FILE_DIRECTORY);
}

#define MAX_SUBDIR 10
EFI_STATUS uefi_write_file_with_dir(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN size)
{
	EFI_STATUS ret;
	EFI_FILE *dirs[MAX_SUBDIR];
	EFI_FILE *file;
	CHAR16 *start;
	CHAR16 *end;
	INTN subdir = 0;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &dirs[0]);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open root directory, error %r\n", ret);
		return ret;
	}
	start = filename;
	for (end = filename; *end; end++) {
		if (*end != '/')
			continue;
		if (start == end) {
			start++;
			continue;
		}

		*end = 0;
		debug("create directory %s\n", start);
		ret = uefi_create_dir(dirs[subdir], &dirs[subdir + 1], start);
		*end = '/';
		if (EFI_ERROR(ret))
			goto out;
		subdir++;
		if (subdir >= MAX_SUBDIR - 1) {
			error(L"too many subdirectories, limit is %d\n", MAX_SUBDIR);
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}
		start = end + 1;
	}
	debug("write file %s\n", start);
	ret = uefi_call_wrapper(dirs[subdir]->Open, 5, dirs[subdir], &file, start, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, &size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	for (; subdir >= 0; subdir--)
		uefi_call_wrapper(dirs[subdir]->Close, 1, dirs[subdir]);

	if (EFI_ERROR(ret))
		error(L"Failed to write file %s: %r\n", filename, ret);
	return ret;
}

void uefi_reset_system(EFI_RESET_TYPE reset_type)
{
	uefi_call_wrapper(RT->ResetSystem, 4, reset_type,
			  EFI_SUCCESS, 0, NULL);
}

void uefi_shutdown(void)
{
	uefi_reset_system(EfiResetShutdown);
}

EFI_STATUS uefi_delete_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename,
				EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Delete, 1, file);

out:
	if (EFI_ERROR(ret) || ret == EFI_WARN_DELETE_FAILURE)
		error(L"Failed to delete file %s:%r\n", filename, ret);

	return ret;
}

BOOLEAN uefi_exist_file(EFI_FILE *parent, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file;

	ret = uefi_call_wrapper(parent->Open, 5, parent, &file, filename,
				EFI_FILE_MODE_READ, 0);
	if (!EFI_ERROR(ret))
		uefi_call_wrapper(file->Close, 1, file);
	else if (ret != EFI_NOT_FOUND) // IO error
		error(L"Failed to found file %s:%r\n", filename, ret);

	return ret == EFI_SUCCESS;
}

BOOLEAN uefi_exist_file_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open volume %s:%r\n", filename, ret);
		return FALSE;
	}

	return uefi_exist_file(root, filename);
}

EFI_STATUS uefi_create_directory(EFI_FILE *parent, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *dir;

	ret = uefi_create_dir(parent, &dir, dirname);

	if (EFI_ERROR(ret)) {
		error(L"Failed to create directory %s:%r\n", dirname, ret);
	} else {
		uefi_call_wrapper(dir->Close, 1, dir);
	}

	return ret;
}

EFI_STATUS uefi_create_directory_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		error(L"Failed to open volume %s:%r\n", dirname, ret);
		return ret;
	}

	return uefi_create_directory(root, dirname);
}

EFI_STATUS uefi_set_simple_var(CHAR8 *name, EFI_GUID *guid, int size, void *data,
			       BOOLEAN persistent)
{
	EFI_STATUS ret;
	CHAR16 *name16 = stra_to_str((CHAR8 *)name);

	if (persistent)
		ret = LibSetNVVariable(name16, guid, size, data);
	else
		ret = LibSetVariable(name16, guid, size, data);

	FreePool(name16);
	return ret;
}

INT8 uefi_get_simple_var(CHAR8 *name, EFI_GUID *guid)
{
	void *buffer;
	UINT64 ret;
	UINTN size;
	CHAR16 *name16 = stra_to_str((CHAR8 *)name);
	buffer = LibGetVariableAndSize(name16, guid, &size);

	if (buffer == NULL) {
		error(L"Failed to get variable %s\n", name16);
		ret = -1;
		goto out;
	}

	if (size > sizeof(ret)) {
		error(L"Tried to get UEFI variable larger than %d bytes (%d bytes)."
		      " Please use an appropriate retrieve method.\n", sizeof(ret), size);
		ret = -1;
		goto out;
	}

	ret = *(INT8 *)buffer;
out:
	FreePool(name16);
	if (buffer)
		FreePool(buffer);
	return ret;
}

EFI_STATUS uefi_usleep(UINTN useconds)
{
	return uefi_call_wrapper(BS->Stall, 1, useconds);
}

EFI_STATUS uefi_msleep(UINTN mseconds)
{
	return uefi_usleep(mseconds * 1000);
}

UINT32 swap_bytes32(UINT32 n)
{
        return ((n & 0x000000FF) << 24) |
		((n & 0x0000FF00) << 8 ) |
		((n & 0x00FF0000) >> 8 ) |
		((n & 0xFF000000) >> 24);
}


UINT16 swap_bytes16(UINT16 n)
{
        return ((n & 0x00FF) << 8) | ((n & 0xFF00) >> 8);
}


void copy_and_swap_guid(EFI_GUID *dst, const EFI_GUID *src)
{
	if (!dst | !src) {
		error(L"copy_and_swap_guid failed (parameter NULL)\n");
		return;
	}

	CopyMem(&dst->Data4, src->Data4, sizeof(src->Data4));
        dst->Data1 = swap_bytes32(src->Data1);
        dst->Data2 = swap_bytes16(src->Data2);
        dst->Data3 = swap_bytes16(src->Data3);
}

EFI_STATUS open_partition(
	IN const EFI_GUID *guid,
	OUT UINT32 *MediaIdPtr,
	OUT EFI_BLOCK_IO **BlockIoPtr,
	OUT EFI_DISK_IO **DiskIoPtr)
{
        EFI_STATUS ret;
        EFI_BLOCK_IO *BlockIo;
        EFI_DISK_IO *DiskIo;
        UINT32 MediaId;
        UINTN NoHandles = 0;
        EFI_HANDLE *HandleBuffer = NULL;

	if (!guid || !MediaIdPtr || !BlockIoPtr || !DiskIoPtr)
		return EFI_INVALID_PARAMETER;

        /* Get a handle on the partition containing the boot image */
        ret = LibLocateHandleByDiskSignature(
		MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
		SIGNATURE_TYPE_GUID,
		(void *)guid,
		&NoHandles,
		&HandleBuffer);
        if (EFI_ERROR(ret) || NoHandles == 0) {
                /* Workaround for old installers which incorrectly wrote
                 * GUIDs strings as little-endian */
                EFI_GUID g;
                copy_and_swap_guid(&g, guid);
                ret = LibLocateHandleByDiskSignature(
			MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
			SIGNATURE_TYPE_GUID,
			(void *)&g,
			&NoHandles,
			&HandleBuffer);
                if (EFI_ERROR(ret)) {
                        error(L"LibLocateHandle", ret);
                        return ret;
                }
        }
        if (NoHandles != 1) {
                error(L"%d handles found for GUID, expecting 1: %g\n",
                      NoHandles, guid);
                ret = EFI_VOLUME_CORRUPTED;
                goto out;
        }

	/* In Fast boot mode, only ESP device is connected to protocols.
	 * We need to specificallty connect the device in order to use it's DiskIoProtocol
	 */
	uefi_call_wrapper(BS->ConnectController, 4, HandleBuffer[0], NULL, NULL, TRUE);

        /* Instantiate BlockIO and DiskIO protocols so we can read various data */
        ret = uefi_call_wrapper(BS->HandleProtocol, 3, HandleBuffer[0],
				&BlockIoProtocol,
				(void **)&BlockIo);
        if (EFI_ERROR(ret)) {
                error(L"HandleProtocol (BlockIoProtocol)\n", ret);
                goto out;;
        }
        ret = uefi_call_wrapper(BS->HandleProtocol, 3, HandleBuffer[0],
				&DiskIoProtocol, (void **)&DiskIo);
        if (EFI_ERROR(ret)) {
                error(L"HandleProtocol (DiskIoProtocol)\n", ret);
                goto out;
        }
        MediaId = BlockIo->Media->MediaId;

        *MediaIdPtr = MediaId;
        *BlockIoPtr = BlockIo;
        *DiskIoPtr = DiskIo;
out:
        FreePool(HandleBuffer);
        return ret;
}

void path_to_dos(CHAR16 *path)
{
	while (*path) {
		if (*path == '/')
			*path = '\\';
		path++;
	}
}

/* Return a newly allocated string containing the concatenation of the
 * two parameters with a space between them
 *
 * return NULL if the two strings are empty or the allocation failed,
 */
CHAR8 *append_strings(CHAR8 *s1, CHAR8 *s2)
{
	INTN len_s1;
	INTN len_s2;
	BOOLEAN space;
	CHAR8 *new;

	len_s1 = s1 ? strlena(s1) : 0;
	len_s2 = s2 ? strlena(s2) : 0;
	space = s1 && s2;

	if (!s1 && !s2)
		return NULL;

	new = AllocatePool(len_s1 + len_s2 + 1 + space);
	if (!new) {
		error(L"Failed to allocate new command line\n");
		return NULL;
	}

	UINTN i = 0;
	if (s1) {
		CopyMem(new, s1, len_s1);
		i += len_s1;
	}
	if (space)
		new[i++] = ' ';
	if (s2) {
		CopyMem(new + i, s2, len_s2);
		i += len_s2;
	}

	new[i] = '\0';
	return new;
}

void dump_buffer(CHAR8 *b, UINTN size)
{
	UINTN i;
	CHAR8 ascii[0x10];
	for (i = 0; i < size; i++) {
		if (i % 0x10 == 0)
			Print(L"%08x:", i);
		if (i % 2 == 0)
			Print(L" ");
		Print(L"%02x", b[i]);
		if (i % 0x10 == 0x0F) {
			UINTN j;
			CHAR8 c;
			for (j = 0; j < 0xF; j++) {
				c = b[j+i-0xF];
				if (c < ' ' || c > '~')
					ascii[j] = '.';
				else
					ascii[j] = c;
			}
			ascii[0xF] = '\0';
			Print(L"  |%a|\n", ascii);
		}
	}
	Print(L"\n");
}

int sprintf(char *str, const char *format, ...)
{
	va_list args;
	UINTN len;
	int ret = -1;
	CHAR16 *str16;
	CHAR16 *format16 = stra_to_str((CHAR8 *)format);

	if (!format16)
		return -1;

	va_start(args, format);
	str16 = VPoolPrint(format16, args);
	va_end(args);

	if (!str16)
		goto free_format16;

	len = StrLen(str16);
	if (str_to_stra((CHAR8 *)str, str16, len) == EFI_SUCCESS) {
		ret = 0;
		str[len] = '\0';
	}

	FreePool(str16);
free_format16:
	FreePool(format16);
	return ret;
}

int snprintf(char *str, size_t size, const char *format, ...)
{
	va_list args;
	int ret;

	va_start(args, format);
	ret = vsnprintf(str, size, format, args);
	va_end(args);
	return ret;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	UINTN len;
	int ret = -1;
	CHAR16 *format16 = stra_to_str((CHAR8 *)format);
	if (!format16)
		return -1;

	CHAR16 *str16 = AllocatePool(size * sizeof(CHAR16));
	if (!str16)
		goto free_format16;

	len = VSPrint(str16, size * sizeof(CHAR16), format16, ap);

	if (str_to_stra((CHAR8 *)str, str16, len + 1) == EFI_SUCCESS) {
		ret = 0;
		str[len] = '\0';
	}

	FreePool(str16);
free_format16:
	FreePool(format16);
	return ret;
}
