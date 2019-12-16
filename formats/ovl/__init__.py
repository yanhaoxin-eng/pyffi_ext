# ***** BEGIN LICENSE BLOCK *****
#
# Copyright (c) 2007-2012, Python File Format Interface
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#	 * Redistributions of source code must retain the above copyright
#	   notice, this list of conditions and the following disclaimer.
#
#	 * Redistributions in binary form must reproduce the above
#	   copyright notice, this list of conditions and the following
#	   disclaimer in the documentation and/or other materials provided
#	   with the distribution.
#
#	 * Neither the name of the Python File Format Interface
#	   project nor the names of its contributors may be used to endorse
#	   or promote products derived from this software without specific
#	   prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# ***** END LICENSE BLOCK *****

import struct
import os
import re
import io
import zlib
import pyffi.object_models.xml
import pyffi.object_models.common
import pyffi.object_models

from pyffi_ext.formats.dds import DdsFormat
from pyffi_ext.formats.ms2 import Ms2Format
from pyffi_ext.formats.bani import BaniFormat
from pyffi_ext.formats.fgm import FgmFormat

def djb(s):
	# calculates DJB hash for string s
	# from https://gist.github.com/mengzhuo/180cd6be8ba9e2743753#file-hash_djb2-py
	hash = 5381
	for x in s:
		hash = (( hash << 5) + hash) + ord(x)
	return hash & 0xFFFFFFFF

	
def get_sized_bytes(data, pos):
	"""Returns content of sized string from bytes. Pos is the position of uint size tag in data str"""
	size = struct.unpack("<I", data[pos:pos+4])[0]
	# print("size",size, data[pos+4 : pos+size+4])
	# todo: this acutally has to reaad size bytes from its proper buffer
	# it only works here because there is no buffer
	# print("size",size, data[pos+4 : pos+30])
	return data[pos+4 : pos+4+size]
	
def get_size(data, pos):
	"""Returns uint at pos from bytes."""
	return struct.unpack("<I", data[pos:pos+4])[0]
	
class OvlFormat(pyffi.object_models.xml.FileFormat):
	"""This class implements the Ovl format."""
	xml_file_name = 'ovl.xml'
	# where to look for ovl.xml and in what order:
	# OVLXMLPATH env var, or OvlFormat module directory
	xml_file_path = [os.getenv('OVLXMLPATH'), os.path.dirname(__file__)]
	# file name regular expression match
	RE_FILENAME = re.compile(r'^.*\.ovl$', re.IGNORECASE)
	# used for comparing floats
	_EPSILON = 0.0001

	# basic types
	int = pyffi.object_models.common.Int
	uint64 = pyffi.object_models.common.UInt64
	uint = pyffi.object_models.common.UInt
	byte = pyffi.object_models.common.Byte
	ubyte = pyffi.object_models.common.UByte
	char = pyffi.object_models.common.Char
	short = pyffi.object_models.common.Short
	ushort = pyffi.object_models.common.UShort
	float = pyffi.object_models.common.Float
	# SizedString = pyffi.object_models.common.SizedString
	ZString = pyffi.object_models.common.ZString
	
	class Data(pyffi.object_models.FileFormat.Data):
		"""A class to contain the actual Ovl data."""
		def __init__(self):
			self.version = 0
			self.flag_2 = 0
			self.header = OvlFormat.Header()
		
		def inspect_quick(self, stream):
			"""Quickly checks if stream contains DDS data, and gets the
			version, by looking at the first 8 bytes.

			:param stream: The stream to inspect.
			:type stream: file
			"""
			pass

		# overriding pyffi.object_models.FileFormat.Data methods
		def get_sized_str_entry(self, name):
			lower_name = name.lower()
			for archive in self.archives:
				for sized_str_entry in archive.sized_str_entries:
					if lower_name == sized_str_entry.lower_name:
						return sized_str_entry
			# still here - error!
			raise KeyError("Can't find a sizedstr entry for {}, not from this archive?".format(name) )
			
		def inspect(self, stream):
			"""Quickly checks if stream contains DDS data, and reads the
			header.

			:param stream: The stream to inspect.
			:type stream: file
			"""
			pos = stream.tell()
			try:
				self.inspect_quick(stream)
				self.header.read(stream, data=self)
				self.version = self.header.version
				self.flag_2 = self.header.flag_2
				self.user_version = self.header.flag_2
			finally:
				stream.seek(pos)
		
		def arr_2_str(self, arr):
			return b"".join(b for b in arr)
		
		def read_z_str(self, stream, pos):
			"""get a zero terminated string from stream at pos """
			stream.seek( pos )
			z_str = OvlFormat.ZString()
			z_str.read(stream, data=self)
			return str(z_str)
			
		def read(self, stream, verbose=0, file="", commands=[], ):
			"""Read a dds file.

			:param stream: The stream from which to read.
			:type stream: ``file``
			"""
			# store commands
			self.commands = commands
			# store file name for later
			if file:
				self.file = file
				self.dir, self.basename = os.path.split(file)
				self.file_no_ext = os.path.splitext(self.file)[0]
			
			self.archives = []
			
			# read the file
			self.header.read(stream, data=self)
			self.version = self.header.version
			self.flag_2 = self.header.flag_2
			self.user_version = self.header.flag_2
			# eoh = stream.tell()
			print(self.header)
			
			# maps OVL hash to final filename + extension
			self.name_hashdict = {}
			# for PZ names
			self.name_list = []
			
			# get the name table, names are separated by 0x00 but are always gotten by array index
			names = self.arr_2_str(self.header.names)
			names_reader = io.BytesIO(names)
			
			archive_names = self.arr_2_str(self.header.archive_names)
			archive_names_reader = io.BytesIO(archive_names)
			
			# for dev purposes so we can populate the file type enum in ovl.xml
			# hash_enums = set()
			
			# add extensions to hash dict
			for mime_entry in self.header.mimes:
				# get the whole mime type string
				mime_type = self.read_z_str(names_reader, mime_entry.offset)
				# only get the extension
				mime_entry.ext = mime_type.split(":")[-1]
				# the stored mime hash is not used anywhere
				self.name_hashdict[mime_entry.mime_hash] = mime_type
				# instead we must calculate the DJB hash of the extension and store that
				# because this is how we find the extension from inside the archive
				self.name_hashdict[djb(mime_entry.ext)] = mime_entry.ext
				
				# for dev purposes only
				# hash_option = (mime_type, '<option value="'+str(mime_entry.mime_hash)+'" name="'+mime_type+'"></option>')
				# hash_enums.add(hash_option)
			# # for development of xml hash enum
			# for mime, xml_str in sorted(hash_enums):
				# print(xml_str)
			
			# add file name to hash dict; ignoring the extension pointer
			for file_entry in self.header.files:
				# get file name from name table
				file_name = self.read_z_str(names_reader, file_entry.offset)
				self.name_hashdict[file_entry.hash] = file_name
				# there seems to be no need for now to link the two
				file_entry.ext = self.header.mimes[file_entry.extension].ext
				file_entry.name = file_name
				self.name_list.append(file_name)
				# print(file_name+"."+file_entry.ext , file_entry.unkn_0, file_entry.unkn_1)
			# return	
			# print(self.name_hashdict)
			
			# create directories
			for dir_entry in self.header.dirs:
				# get dir name from name table
				dir_name = self.read_z_str(names_reader, dir_entry.offset)
				# fix up the name
				dir = os.path.normpath(os.path.join(os.getcwd(), dir_name.lstrip("..\\")) )
				# create dir, do nothing if it already exists
				# os.makedirs(dir, exist_ok=True)
				# print(dir)
			
			# get names of all texture assets
			for texture_entry in self.header.textures:
				# nb. 4 unknowns per texture
				try:
					name = self.name_hashdict[texture_entry.hash]
				except:
					# this seems to happen for main.ovl - external textures?
					name = "bad hash"
				# print(name, texture_entry.unknown_1, texture_entry.unknown_2, texture_entry.unknown_3, texture_entry.unknown_4, texture_entry.unknown_5, texture_entry.unknown_6)#, texture_entry.unknown_7)
				
			# print(sorted(set([t.unknown_6 for t in self.header.textures])))
			# print(textures)
			ovs_dict = {}
			for archive_i, archive_entry in enumerate(self.header.archives):
				archive_entry.name = self.read_z_str(archive_names_reader, archive_entry.offset)
				print("\nREADING ARCHIVE: {}".format(archive_entry.name))
				# skip archives that are empty
				if archive_entry.compressed_size == 0:
					print("archive is empty")
					continue
				# those point to external ovs archives
				if archive_i > 0:
					# JWE style
					if self.flag_2 == 24724:
						archive_entry.ovs_path = self.file_no_ext+".ovs."+archive_entry.name.lower()
					# PZ Style
					elif self.flag_2 == 8340:
						archive_entry.ovs_path = self.file_no_ext+".ovs"
					else:
						print("unsupported flag_2", self.flag_2)
						return
					# print(archive_entry.ovs_path)
					# make sure that the ovs exists
					if not os.path.exists(archive_entry.ovs_path):
						raise FileNotFoundError("OVS file not found. Make sure is is here: \n"+archive_entry.ovs_path)
					# gotta keep them open because more than one archive can live in one ovs file eg PZ inspector
					if archive_entry.ovs_path not in ovs_dict:
						ovs_dict[archive_entry.ovs_path] = open(archive_entry.ovs_path, 'rb')
					
					# todo: account for OVS offsets specified in archive_entry
					# todo: footer bytes in OVS?
					self.unzip(ovs_dict[archive_entry.ovs_path], archive_entry, archive_i, save_temp_dat = self.file+"_"+archive_entry.name+".dat")
				else:
					start_pos = stream.tell()
					# seek from eof backwards to zlib
					stream.seek(-archive_entry.compressed_size, 2)
					# see if we ended up at the same position
					if start_pos != stream.tell():
						print("Undecoded data after header, adjusted cursor")
						print("end of decoding",start_pos)
						print("should be at",stream.tell())
					self.unzip(stream, archive_entry, archive_i, save_temp_dat = self.file+"_"+archive_entry.name+".dat")
			
			# find texstream buffers
			for sized_str_entry in self.archives[0].sized_str_entries:
				if sized_str_entry.ext == "tex":
					for lod_i in range(3):
						for archive in self.archives[1:]:
							for other_sizedstr in archive.sized_str_entries:
								if sized_str_entry.basename in other_sizedstr.name and "_lod"+str(lod_i) in other_sizedstr.name:
									sized_str_entry.data_entry.buffers.extend(other_sizedstr.data_entry.buffers)
								
			# postprocessing of data buffers
			for archive in self.archives:
				for data_entry in archive.data_entries:
					# just sort buffers by their index value
					data_entry.update_buffers()
			
			# print(len(self.archives))
				
			# # we don't use context manager so gotta close them
			# for ovs_file in ovs_dict.values():
				# ovs_file.close()
				
		def unzip(self, stream, archive_entry, archive_i, save_temp_dat=""):
			zipped = stream.read(archive_entry.compressed_size)
			print("Reading",archive_entry.compressed_size, len(zipped))
			self.zlib_header = zipped[:2]
			zlib_compressed_data = zipped[2:]
			# https://stackoverflow.com/questions/1838699/how-can-i-decompress-a-gzip-stream-with-zlib
			# we avoid the two zlib magic bytes to get our unzipped content
			zlib_data = bytearray( zlib.decompress(zlib_compressed_data, wbits = -zlib.MAX_WBITS) )
			if save_temp_dat and "write_dat" in self.commands:
				# for debugging, write deflated content to dat
				with open(save_temp_dat, 'wb') as out:
					out.write(zlib_data)
			# now read the archive stream
			
			archive = OvlFormat.Archive(self, zlib_data, archive_entry, archive_i)
			archive.read_archive( archive.stream )
			self.archives.append( archive )

		def write(self, stream, verbose=0, file_path = ""):
			"""Write a dds file.

			:param stream: The stream to which to write.
			:type stream: ``file``
			:param verbose: The level of verbosity.
			:type verbose: ``int``
			"""
			
			print("Writing OVL")
			
			exp_dir = os.path.dirname(file_path)
			ovs_dict = {}
			# compress data stream
			for i, (archive_entry, archive) in enumerate(zip(self.header.archives, self.archives)):
				# write archive into bytes IO stream
				temp_archive_writer = io.BytesIO()
				archive.write_archive(temp_archive_writer)
				# compress data
				uncompressed_bytes = temp_archive_writer.getvalue()
				compressed = zlib.compress(uncompressed_bytes)
				archive_entry.uncompressed_size = len(uncompressed_bytes)
				archive_entry.compressed_size = len(compressed)
				if i == 0:
					ovl_compressed = compressed
					archive_entry.read_start = 0
				else:
					exp_path = os.path.join(exp_dir, os.path.basename(archive_entry.ovs_path) )
					# gotta keep them open because more than one archive can live in one ovs file eg PZ inspector
					if exp_path not in ovs_dict:
						ovs_dict[exp_path] = open(exp_path, 'wb')
					
					# todo: account for OVS offsets specified in archive_entry
					# todo: footer bytes in OVS?
					ovs_stream = ovs_dict[exp_path]
					
					archive_entry.read_start = ovs_stream.tell()
					ovs_stream.write(compressed)
			
			
			with open(file_path, 'wb') as ovl_stream:
				# first header
				self.header.write(ovl_stream, data=self)
				# write zlib block
				ovl_stream.write(ovl_compressed)
				
			# archive_entry = self.header.archives[0]
			# old_size = int(archive_entry.compressed_size)
			# add size of zlib header
			# new_size = # + 2
			# print("old size:",old_size)
			# print("new size:",new_size)
			# print("zlib magic",self.zlib_header)
			
			# we don't use context manager so gotta close them
			for ovs_file in ovs_dict.values():
				ovs_file.close()
			
		
		
	class BufferEntry:
		def read_data(self, archive):
			"""Load data from archive stream into self for modification and io"""
			self.data = archive.stream.read(self.size)

		def update_data(self, data):
			"""Set data internal data so it can be written on save and update the size value"""
			self.data = data
			self.size = len(data)
			
	class DataEntry:
		def update_data(self, datas):
			"""Load datas into this DataEntry's buffers, and update its size values according to an assumed pattern
			data : list of bytes object, each representing the data of one buffer for this data entry"""
			for buffer, data in zip(self.buffers, datas):
				buffer.update_data(data)
			# update data 0, 1 size
			total = sum( len(d) for d in datas)
			if len(datas) == 1:
				self.size_1 = len(datas[0])
				self.size_2 = 0
			elif len(datas) == 2:
				self.size_1 = 0
				self.size_2 = sum( len(d) for d in datas )
			elif len(datas) > 2:
				self.size_1 = sum( len(d) for d in datas[:-1] )
				self.size_2 = len(datas[-1])
			# print(total)
			# print(self.size_1)
			# print(self.size_2)
		
		def update_buffers(self,):
			# sort the buffer entries of each data entry by their index
			self.buffers.sort( key=lambda buffer: buffer.index )
			# trim to valid buffers (ignore ones that run out of count, usually zero-sized ones)
			# self.buffers = self.buffers[:self.buffer_count]
			# self.buffers = list(b for b in self.buffers if b.size)
			
		@property
		def buffer_datas(self):
			"""Get data for each non-empty buffer (should have been sorted before)"""
			return list(buffer.data for buffer in self.buffers if buffer.size)
	
	class HeaderPointer:
		def read_data(self, archive):
			"""Load data from archive header data readers into pointer for modification and io"""

			if self.header_index == 4294967295:
				self.data = None
			else:
				header_reader = archive.header_entries[self.header_index].data
				header_reader.seek(self.data_offset)
				self.data = header_reader.read(self.data_size)
			
		def write_data(self, archive, update_copies=False):
			"""Write data to header data, update offset, also for copies if told"""

			if self.header_index == 4294967295:
				pass
			else:
				# get header data to write into
				writer = archive.header_entries[self.header_index].data
				# update data offset
				self.data_offset = writer.tell()
				if update_copies:
					for other_pointer in self.copies:
						other_pointer.data_offset = writer.tell()
				# write data to io, adjusting the cursor for that header
				writer.write(self.data)
			
		def link_to_header(self, archive):
			"""Store this pointer in suitable header entry"""

			if self.header_index == 4294967295:
				pass
			else:
				# get header entry
				entry = archive.header_entries[self.header_index]
				if self.data_offset not in entry.pointer_map:
					entry.pointer_map[self.data_offset] = []
				entry.pointer_map[self.data_offset].append(self)

		def update_data(self, data, update_copies=False):
			"""Update data and size param"""
			# todo - enforce modulo padding here?
			self.data = data
			self.data_size = len(data)
			# update other pointers if asked to by the injector
			if update_copies:
				for other_pointer in self.copies:
					other_pointer.update_data(data)
			
		def get_reader(self):
			return io.BytesIO(self.data)

		def read_as(self, pyffi_cls, data, num=1):
			"""Return self.data as pyffi cls
			Data must be an object that has version & user_version attributes"""
			reader = self.get_reader()
			insts = []
			for i in range(num):
				inst = pyffi_cls()
				inst.read(reader, data=data)
				insts.append(inst)
			return insts

	class Archive(pyffi.object_models.FileFormat.Data):
		"""A class to contain the actual Ovl data."""
		def __init__(self, header, zlib_data, archive_entry, archive_index = 0):
			# the main ovl header
			self.header = header
			
			self.zlib_data = zlib_data
			# just to get read() api on bytes object
			self.stream = io.BytesIO(zlib_data)
			self.archive_entry = archive_entry
			self.archive_index = archive_index
			self.version = self.header.version
			self.user_version = self.header.user_version

		def read_z_str(self, stream, pos):
			"""get a zero terminated string from stream at pos """
			stream.seek( pos )
			z_str = OvlFormat.ZString()
			z_str.read(stream, data=self)
			return str(z_str)
		
		def indir(self, name):
			return os.path.join( self.dir, name)
			
		def get_name(self, entry):
			"""Fetch a filename from hash dict"""
			# JWE style
			if self.header.flag_2 == 24724:
				# print("JWE ids",entry.file_hash, entry.ext_hash)
				try:
					n = self.header.name_hashdict[entry.file_hash]
				except:
					n = "NONAME"
				try:
					e = self.header.name_hashdict[entry.ext_hash]
				except:
					e = "UNKNOWN"
			# PZ Style
			elif self.header.flag_2 == 8340:
				# print("PZ ids",entry.file_hash, entry.ext_hash)
				try:
					n = self.header.name_list[entry.file_hash]
				except:
					n = "NONAME"
				try:
					# e = self.ext_list[entry.ext_hash]
					e = self.header.name_hashdict[entry.ext_hash]
				except:
					e = "UNKNOWN"
			return n + "." + e
		
		def write_archive(self, stream):

			for header_entry in self.header_entries:
				# clear io objects
				header_entry.data = io.BytesIO()
				# maintain sorting order
				# grab the first pointer for each address
				# it is assumed that subsequent pointers to that address share the same data
				sorted_first_pointers = [pointers[0] for offset, pointers in sorted(header_entry.pointer_map.items()) ]
				# write updated strings
				for pointer in sorted_first_pointers:
					pointer.write_data(self, update_copies=True)

			# do this first so header entries can be updated
			header_data_writer = io.BytesIO()
			# the ugly stuff with all fragments and sizedstr entries
			for header_entry in self.header_entries:
				header_data_bytes = header_entry.data.getvalue()
				# JWE style
				if self.header.flag_2 == 24724:
					header_entry.offset = header_data_writer.tell()
				# PZ Style
				elif self.header.flag_2 == 8340:
					header_entry.offset = self.archive_entry.ovs_header_offset + header_data_writer.tell()
				header_entry.size = len(header_data_bytes)
				header_data_writer.write( header_data_bytes )
			
			# write out all entries
			for l in (self.header_types, self.header_entries, self.data_entries, 
					  self.buffer_entries, self.sized_str_entries, self.fragments):
				for entry in l:
					entry.write(stream, self)
			# write set & asset stuff
			self.set_header.write(stream, self)
			# write the header data containing all the pointers' datas
			stream.write( header_data_writer.getvalue() )
			
			# write buffer data
			for b in self.buffers_io_order:
				stream.write(b.data)
				
			# do some calculations
			# self.archive_entry.uncompressed_size = stream.tell()
			# self.archive_entry.uncompressed_size = self.calc_uncompressed_size()
		
		def calc_uncompressed_size(self, ):
			"""Calculate the size of the whole decompressed stream for this archive"""
			
			# TODO: this is apparently wrong during write_archive, as if something wasn't properly updated
			
			check_data_size_1 = 0
			check_data_size_2 = 0
			for data_entry in self.data_entries:
				check_data_size_1 += data_entry.size_1
				check_data_size_2 += data_entry.size_2
			return self.header_size + self.calc_header_data_size() + check_data_size_1 + check_data_size_2
			
		def calc_header_data_size(self, ):
			"""Calculate the size of the whole data entry region that sizedstr and fragment entries point into"""
			return sum( header_entry.size for header_entry in self.header_entries )
			
		def read_archive(self, stream):
			"""Reads a deflated archive stream"""
			
			# read the entries in archive order
			self.read_header_types()
			self.read_header_entries()
			self.read_data_entries()
			self.read_buffer_entries()
			self.read_sizedstr_entries()
			self.read_fragment_entries()

			set_data_offset = stream.tell()
			print("Set header address", set_data_offset)
			self.read_sets_assets()
			self.map_assets()
	
			# size check again
			self.header_size = stream.tell()
			set_data_size = self.header_size - set_data_offset
			if set_data_size != self.archive_entry.set_data_size:
				raise AttributeError("Set data size incorrect (got {}, expected {})!".format(set_data_size, self.archive_entry.set_data_size) )
			
			# another integrity check
			if self.calc_uncompressed_size() != self.archive_entry.uncompressed_size:
				raise AttributeError("Archive.uncompressed_size ({}) does not match calculated size ({})".format(self.archive_entry.uncompressed_size, self.calc_uncompressed_size()))
			
			# go back to header offset
			stream.seek(self.header_size)
			# add IO object to every header_entry
			for header_entry in self.header_entries:
				header_entry.data = io.BytesIO( stream.read(header_entry.size) )
			
			self.check_header_data_size = self.calc_header_data_size()
			self.map_pointers()
			self.calc_pointer_addresses()
			self.calc_pointer_sizes()
			self.populate_pointers()
			
			self.map_frags()
			self.map_buffers()
			
			if "write_frag_log" in self.header.commands:
				self.write_frag_log()
		
		def read_header_types(self):
			"""Reads a HeaderType struct for the count"""
			self.header_types = []
			# for checks
			check_header_types = 0

			# read header types
			print("Header Types")
			for x in range(self.archive_entry.num_header_types):
				header_type = OvlFormat.HeaderType()
				header_type.read(self.stream, self)
				# add this header_type's count to check var
				check_header_types += header_type.num_headers
				self.header_types.append(header_type)
				# print(header_type)
			
			# ensure that the sum equals the value specified by the archive_entry
			if check_header_types != self.archive_entry.num_headers:
				raise AttributeError("Mismatch between total amount of headers")

		def read_header_entries(self):
			self.header_entries = []
			# # a dict keyed with header type hashes 
			# headers_by_type = {}
			# read all header entries
			print("Header Entries")
			for header_type in self.header_types:
				for i in range(header_type.num_headers):
					header_entry = OvlFormat.HeaderEntry()
					header_entry.read(self.stream, self)
					header_entry.header_type = header_type
					header_entry.type = header_type.type
					self.header_entries.append(header_entry)
					# print(header_entry)
					header_entry.name = self.get_name(header_entry)
					header_entry.basename, header_entry.ext = os.path.splitext(header_entry.name)
					header_entry.ext = header_entry.ext[1:]
					print("header",header_entry.name)
					print("size",header_entry.size)
					# print("header",header_entry)
					
					# todo: can we make use of this again for an improved fragment getter?
					# # create list if required
					# ext_hash = header_entry.ext_hash
					# if ext_hash not in headers_by_type:
						# headers_by_type[ext_hash] = []
					# # append this header so we can access by type & index per type
					# headers_by_type[ext_hash].append(header_entry)

		def read_data_entries(self):
			self.data_entries = []
			check_buffer_count = 0
			# read all data entries
			print("Data Entries")
			for i in range(self.archive_entry.num_datas):
				data_entry = OvlFormat.DataEntry()
				data_entry.read(self.stream, self)
				self.data_entries.append(data_entry)
				check_buffer_count += data_entry.buffer_count
				
				data_entry.name = self.get_name(data_entry)
				print("data",data_entry.name)
				# print(data_entry)
				
			print("Num data_entry Entries",len(self.data_entries))
			# print("Num header.Num Files",header)
				
			if check_buffer_count != self.archive_entry.num_buffers:
				raise AttributeError("Wrong buffer count (expected "+str(self.archive_entry.num_buffers)+")!")
			
			# todo: figure out how barbasol calculates this
			# aka self.archive_entry.data2_size
			# if check_data_size_2 != self.archive_entry.size_2:
				# raise AttributeError("Data size does not match")

		def read_buffer_entries(self):
			self.buffer_entries = []
			print("Buffer Entries")
			# read all Buffer entries
			for i in range(self.archive_entry.num_buffers):
				buffer_entry = OvlFormat.BufferEntry()
				buffer_entry.read(self.stream, self)
				self.buffer_entries.append(buffer_entry)
				# print(buffer_entry)
			print("Buffers",len(self.buffer_entries))

		def read_sizedstr_entries(self):
			self.sized_str_entries = []
			print("SizedString Entries")
			# read all file entries type b
			for i in range(self.archive_entry.num_files):
				sized_str_entry = OvlFormat.SizedStringEntry()
				sized_str_entry.read(self.stream, self)
				sized_str_entry.name = self.get_name(sized_str_entry)
				sized_str_entry.lower_name = sized_str_entry.name.lower()
				sized_str_entry.basename, sized_str_entry.ext = os.path.splitext(sized_str_entry.name)
				sized_str_entry.ext = sized_str_entry.ext[1:]
				sized_str_entry.children = []
				sized_str_entry.parent = None
				sized_str_entry.fragments = []
				sized_str_entry.model_data_frags = []
				sized_str_entry.model_count = 0
				# get data entry for link to buffers, or none
				sized_str_entry.data_entry = self.find_entry(self.data_entries, sized_str_entry.file_hash, sized_str_entry.ext_hash)
				# print("\nSizedString",sized_str_entry.name,sized_str_entry.pointers[0].data_offset,sized_str_entry.header_index)#2476
				# print(sized_str_entry.data_entry)
				# print(sized_str_entry)
				self.sized_str_entries.append(sized_str_entry)
			print("Num SizedString Entries",len(self.sized_str_entries))

		def read_fragment_entries(self):
			self.fragments = []
			print("Fragment Entries")
			# read all self.fragments
			for i in range(self.archive_entry.num_fragments):
				fragment = OvlFormat.Fragment()
				fragment.read(self.stream, self)
				# we assign these later
				fragment.done = False
				fragment.lod = False
				fragment.name = None
				self.fragments.append(fragment)
			print("Num Fragment Entries",len(self.fragments))

		def read_sets_assets(self):
			"""Read the set header block that defines sets and assets"""
			print("Reading sets and assets...")
			self.set_header = OvlFormat.SetHeader()
			self.set_header.read(self.stream, self)
			# print(self.set_header)
			# signature check
			if not (self.set_header.sig_a == 1065336831 and self.set_header.sig_b == 16909320):
				raise AttributeError("Set header signature check failed!")
			# print("Set Entries")
			# read all set entries
			for set_entry in self.set_header.sets:
				set_entry.name = self.get_name(set_entry)
			for asset_entry in self.set_header.assets:
				asset_entry.name = self.get_name(asset_entry)
				asset_entry.entry = self.sized_str_entries[asset_entry.file_index]
			
		def calc_pointer_addresses(self):
			# store absolute read addresses from the start of file
			for entry in self.fragments + self.sized_str_entries:
				# for access from start of file
				for pointer in entry.pointers:
					# some have max_uint as a header value, what do they refer to
					if pointer.header_index == 4294967295:
						# print("Warning: {} has no header index (-1)".format(entry.name))
						pointer.header = 9999999
						pointer.type = 9999999
						pointer.address = 9999999
						# sized_str_entry.parent 
					else:
						pointer.header = self.header_entries[pointer.header_index]
						# store type number of each header entry
						pointer.type = pointer.header.type
						pointer.address = self.header_size + pointer.header.offset + pointer.data_offset
			
		def calc_pointer_sizes(self):
			"""Assign an estimated size to every pointer"""
			# calculate pointer data sizes
			for entry in self.header_entries:
				# make them unique and sort them
				sorted_addresses = sorted( set( entry.pointer_map.keys() ) )
				# add the end of the header data block
				sorted_addresses.append(entry.size)
				# get the size of each fragment: find the next entry's address and substract it from address
				for pointers in entry.pointer_map.values():
					# todo could optimize using update_copies
					for pointer in pointers:
						# get the offset of the next entry that points into this buffer
						ind = sorted_addresses.index(pointer.data_offset) + 1
						# set data size for this entry
						pointer.data_size = sorted_addresses[ind] - pointer.data_offset

		def map_pointers(self):
			"""Assign list of copies to every pointer so they can be updated with the same data easily"""
			print("\nMapping pointers")
			# reset pointer map for each header entry
			for header_entry in self.header_entries:
				header_entry.pointer_map = {}
			# append all valid pointers to their respective dicts
			for entry in self.fragments + self.sized_str_entries:
				for pointer in entry.pointers:
					pointer.link_to_header(self)
			for header_entry in self.header_entries:
				# for every pointer, store any other pointer that points to the same address
				for offset, pointers in header_entry.pointer_map.items():
					for p in pointers:
						p.copies = [po for po in pointers if po != p]
		
		def populate_pointers(self):
			"""Load data for every pointer"""
			for entry in self.fragments + self.sized_str_entries:
				for pointer in entry.pointers:
					pointer.read_data(self)
			
		def map_assets(self):
			"""Store start and stop indices to asset entries, translate hierarchy to sizedstr entries"""
			# store start and stop asset indices
			for i, set_entry in enumerate(self.set_header.sets):
				# for the last entry
				if i == self.set_header.set_count-1:
					set_entry.end = self.set_header.asset_count
				# store start of the next one as this one's end
				else:
					set_entry.end = self.set_header.sets[i+1].start
				# map assets to entry
				set_entry.assets = self.set_header.assets[set_entry.start : set_entry.end]
				# print("SET:",set_entry.name)
				# print("ASSETS:",[a.name for a in set_entry.assets])
				# store the references on the corresponding sized str entry
				sized_str_entry = self.find_entry(self.sized_str_entries, set_entry.file_hash, set_entry.ext_hash)
				sized_str_entry.children = [self.sized_str_entries[a.file_index] for a in set_entry.assets]
				for child in sized_str_entry.children:
					child.parent = sized_str_entry

		def collect_matcol(self, sized_str_entry, address_0_fragments):
			print("\nMATCOL:",sized_str_entry.name)
			f0 = self.get_frag_after(address_0_fragments, ((4,4),), sized_str_entry.pointers[0].address)[0]
			# print(f0)
			#0,0,collection count,0
			f0_d0 = struct.unpack("<4I", f0.pointers[0].data)
			#flag (3=variant, 2=layered) , 0
			has_texture_list_frag = len(f0.pointers[1].data) == 8
			if has_texture_list_frag:
				f0_d1 = struct.unpack("<2I", f0.pointers[1].data)
			else:
				f0_d1 = struct.unpack("<6I", f0.pointers[1].data)
			print("f0_d0", f0_d0)
			print("f0_d1", f0_d1)
			is_variant = f0_d1[0] == 3
			is_layered = f0_d1[0] == 2
			print("has_texture_list_frag",has_texture_list_frag)
			print("is_variant",is_variant)
			print("is_layered",is_layered)
			# print(f1)
			if has_texture_list_frag:
				f1 = self.get_frag_after(address_0_fragments, ((4,4),), f0.pointers[1].address)[0]
				f1_d0 = struct.unpack("<4I", f1.pointers[0].data)
				print("f1_d0", f1_d0)
				tex_count = f1_d0[2]
				print("tex_count",tex_count)
				for t in range(tex_count):
					tex_frags = self.get_frag_after(address_0_fragments, ((4,6),(4,6),(4,6)), f1.pointers[1].address)
					for tex in tex_frags:
						print(tex.pointers[1].data)
			
			# material pointer frag
			f2 = self.get_frag_after(address_0_fragments, ((4,4),), f0.pointers[1].address)[0]
			f2_d0 = struct.unpack("<6I", f2.pointers[0].data)
			print("f2_d0",f2_d0)
			mat_count = f2_d0[2]
			print("mat_count",mat_count)
			if is_variant:
				for t in range(mat_count):
					mat_frags = self.get_frag_after(address_0_fragments, ((4,6),), f2.pointers[1].address)
					for mat in mat_frags:
						print(mat.pointers[1].data)
			elif is_layered:
				for t in range(mat_count):
					mat_frags = self.get_frag_after(address_0_fragments, ((4,6),(4,4),(4,4)), f2.pointers[1].address)
					# for mat in mat_frags:
					m2, m1, m0 = mat_frags
					print(m0.pointers[1].data)
					# print(m0.pointers[0].address, m1.pointers[0].address, m2.pointers[0].address)
					m1_d0 = struct.unpack("<8I", m1.pointers[0].data)
					m1_info_count = m1_d0[2]
					print("m1_info_count",m1_info_count)
					for i in range(m1_info_count):
						info = self.get_frag_after(address_0_fragments, ((4,6),), m1.pointers[1].address)[0]
						# 0,0,byte flag,byte flag,byte flag,byte flag,float,float,float,float,0
						info_d0 = struct.unpack("<2I4B4fI", info.pointers[0].data)
						print(info.pointers[1].data, info_d0)
					m2_d0 = struct.unpack("<4I", m2.pointers[0].data)
					m2_attrib_count = m2_d0[2]
					print("m2_attrib_count",m2_attrib_count)
					for i in range(m2_attrib_count):
						attr = self.get_frag_after(address_0_fragments, ((4,6),), m2.pointers[1].address)[0]
						# 0,0,byte flag,byte flag,byte flag,byte flag,float,float,float,float,0
						attr_d0 = struct.unpack("<2I4BI", attr.pointers[0].data)
						print(attr.pointers[1].data, attr_d0)
					
		def map_frags(self):
			# these are first reversed and then sorted by file type as defined in frag_order
			sorted_sized_str_entries = []
			reversed_sized_str_entries = list(reversed(self.sized_str_entries))
			frag_order = ( "mdl2", "motiongraph", "fgm", "ms2", "banis", "bani", "spl", "manis", "mani", "tex", "txt", "enumnamer", "motiongraphvars", "hier", "lua", "xmlconfig", "assetpkg", "userinterfaceicondata", "materialcollection")
			
			# count mdl2 files
			ms2_count = 0
			mdl2_count = 0
			motiongraph_count = 0
			motionvars_count = 0
			enumnamer_count = 0
			for ext in frag_order:
				for sized_str_entry in reversed_sized_str_entries:
					if sized_str_entry.ext == ext:
						if ext == "ms2":
							ms2_count += 1
						elif ext == "mdl2":
							mdl2_count += 1
						elif ext == "motiongraph":
							motiongraph_count += 1
						elif ext == "motiongraphvars":
							motionvars_count += 1
						elif ext == "enumnamer":
							enumnamer_count += 1
						sorted_sized_str_entries.append(sized_str_entry)
						# print(sized_str_entry.name)
			print("\nMapping SizedStr to Fragment")
			# if there is more than one model we have an extra fgm fragment that links fgm to model
			print("ms2_count ",ms2_count)
			# todo: document more of these type requirements
			dic = { 
					"ms2": ( (2,2), (2,2), (2,2), ),
					"bani": ( (2,2), ),
					"tex": ( (3, 3), (3,7), ),
                    "xmlconfig": ( (2, 2), ),
					# "txt": ( ),
					# "enumnamer": ( (4,4), ),
					# "motiongraphvars": ( (4,4), (4,6), (4,6), (4,6), (4,6), (4,6), (4,6), (4,6), ),
					# "hier": ( (4,6) for x in range(19) ),
					"spl": ( (2,2), ),
					#"mani": (),
					"manis": (),
					#"motiongraph": ( ),
					#"matcol": (),
					"lua": ( (2,2), (2,2), ), #need to figure out load order still
					"assetpkg": ( (4,6), ), #need to figure out load order still
                    "userinterfaceicondata": ( (4,6), (4,6), ),
					#"world": will be a variable length one with a 4,4; 4,6; then another variable length 4,6 set : set world before assetpkg in order
					#"fdb": (), 

			}
			
			# we go from the end
			reversed_fragments = list(reversed(self.fragments))
			address_0_fragments = list(sorted(self.fragments, key=lambda f: f.pointers[0].address))
			for frag in self.fragments:
				if (self.header.flag_2 == 24724 and frag.pointers[0].data_size == 64 and frag.pointers[1].data_size == 48) \
				or (self.header.flag_2 == 8340  and frag.pointers[0].data_size == 64 and frag.pointers[1].data_size == 56):
					frag.lod = True
					frag.done = True
				else:
					frag.lod = False
					frag.done = False
			
			for sized_str_entry in sorted_sized_str_entries:
				# get fixed fragments
				if sized_str_entry.ext in dic:
					print("Collecting fragments for",sized_str_entry.name,sized_str_entry.pointers[0].address)
					t = dic[sized_str_entry.ext]
					# get and set fragments
					sized_str_entry.fragments = self.get_frag_after(address_0_fragments, t, sized_str_entry.pointers[0].address)
				
				elif sized_str_entry.ext == "fgm":
					sized_str_entry.fragments = self.get_frag_after_terminator(address_0_fragments, (2,2), sized_str_entry.pointers[0].address)
				
				elif sized_str_entry.ext == "materialcollection":
					self.collect_matcol( sized_str_entry, address_0_fragments)
			# get all fixed fragments, 5 per file
			t = ( (2,2) for x in range(mdl2_count*5))
			# we have no initpos for these as the mdl2 entries have no data offset
			mdl2_fixed_frags = self.get_mdl2frag(address_0_fragments, t )
			
			# second pass: collect model fragments
			# now assign the mdl2 frags to their sized str entry
			fixed_t = tuple( (2,2) for x in range(5))
			# go in reversed set entry, forward asset entry order
			set_entries = reversed(self.set_header.sets) if "reverse_sets" in self.header.commands else self.set_header.sets
			for set_entry in set_entries:
				for asset_entry in set_entry.assets:
					assert(asset_entry.name == asset_entry.entry.name)
					sized_str_entry = asset_entry.entry
					if sized_str_entry.ext == "mdl2":
						sized_str_entry.fragments = self.get_frag2(mdl2_fixed_frags, fixed_t)
						print("Collecting model fragments for",sized_str_entry.name)
						
						# todo: get model count from CoreModelInfo
						# but that needs to get the first one from the ms2
						
						# hack: infer the model count from the fragment with material1 data
						orange_frag = sized_str_entry.fragments[2]
						orange_frag_count = orange_frag.pointers[1].data_size // 4
						mats = orange_frag.pointers[1].read_as(Ms2Format.Material1, self, num = orange_frag_count)
						model_indices = [m.model_index for m in mats]
						print("orange_frag_count",orange_frag_count)
						print(model_indices)
						if model_indices:
							sized_str_entry.model_count = max(model_indices) + 1
						else:
							print("probably bug from refactoring, found no models")
							sized_str_entry.model_count = 0

						# todo: remove once CoreModelInfo is implemented
						# check for empty mdl2s by ensuring that one of the fixed self.fragments has the correct size
						yellow_frag = sized_str_entry.fragments[3]
						if yellow_frag.pointers[1].data_size != 64:
							sized_str_entry.model_count = 0
							print("No model frags for",sized_str_entry.name)
						# create type template from count
						t = ( (2,2) for x in range(sized_str_entry.model_count) )
						# get and set self.fragments
						sized_str_entry.model_data_frags = self.get_model_data_frags(address_0_fragments, t)
				
			# # for debugging only:
			for sized_str_entry in sorted_sized_str_entries:
				for frag in sized_str_entry.model_data_frags + sized_str_entry.fragments:
					frag.name = sized_str_entry.name
							
			# for header_i, header_entry in enumerate(self.header_entries):
				# print("Header {} with unknown count {}".format(header_i, header_entry.num_files))
				
			# print("\nFrag map")
			# frag_lists = (self.fragments, address_0_fragments )
			# for frag_list in frag_lists:
				# for i, frag in enumerate(frag_list):
					# print(i, tuple( (p.address, p.data_size) for p in frag.pointers), frag.name, tuple(p.type for p in frag.pointers))
				# print("    ")
			
			# test mapping of children from set entries to sized str entries
			# for i, s in enumerate(sorted_sized_str_entries):
				# print(i, s.name, [c.name for c in s.children])
			# print()

		def map_buffers(self):
			"""Map buffers to data entries, sort buffers into load order, populate buffers with data"""
			print("\nMapping buffers")

			# this holds the buffers in the order they are read from the file
			self.buffers_io_order = []
			
			# sequentially attach buffers to data entries by each entry's buffer count
			buff_ind = 0
			for i, data in enumerate(self.data_entries):
				data.buffers = []
				for j in range(data.buffer_count):
					# print("data",i,"buffer",j, "buff_ind",buff_ind)
					buffer = self.buffer_entries[buff_ind]
					# also give each buffer a reference to data so we can access it later
					buffer.data_entry = data
					data.buffers.append(buffer)
					buff_ind +=1
			
			# only do this if there are any data entries so that max() doesn't choke 
			if self.data_entries:
				# check how many buffers occur at max in one data block
				max_buffers_per_data = max([data.buffer_count for data in self.data_entries])
				# first read the first buffer for every file
				# then the second if it has any
				# and so on, until there is no data entry left with unprocessed buffers
				for i in range(max_buffers_per_data):
					for data in self.data_entries:
						if i < data.buffer_count:
							self.buffers_io_order.append(data.buffers[i])

			# finally, we have the buffers in the correct sorting so we can read their contents
			print("\nReading from buffers")
			self.stream.seek(self.header_size + self.check_header_data_size)
			for buffer in self.buffers_io_order:
				# read buffer data and store it in buffer object
				buffer.read_data(self)
		
		def write_frag_log(self,):
			# # this is just for developing to see which unique attributes occur across a list of entries
			# ext_hashes = sorted(set([f.offset for f in self.header.files]))
			# print(ext_hashes)
			# # this is just for developing to see which unique attributes occur across a list of entries
			# ext_hashes = sorted(set([f.size for f in self.fragments]))
			# print(ext_hashes)
			self.dir = os.getcwd()
			# # for development; collect info about fragment types			
			frag_log = "self.fragments > sizedstr\nfragments in file order"
			for i, frag in enumerate(sorted(self.fragments, key=lambda f: f.pointers[0].address)):
				# #frag_log+="\n\nFragment nr "+str(i)
				# #frag_log+="\nHeader types "+str(f.type_0)+" "+str(f.type_1)
				# #frag_log+="\nEntry "+str(f.header_index_0)+" "+str(f.data_offset_0)+" "+str(f.header_index_1)+" "+str(f.data_offset_1)
				# #frag_log+="\nSized str "+str(f.sized_str_entry_index)+" "+str(f.name)
				frag_log+= "\n"+str(i)+" "+str(frag.pointers[0].address)+" "+str(frag.pointers[0].data_size)+" "+str(frag.pointers[1].address)+" "+str(frag.pointers[1].data_size)+" "+str(frag.name)+" "+str(frag.pointers[0].type)+" "+str(frag.pointers[1].type)
			with open(self.indir("frag"+str(self.archive_index)+".log"), "w") as f:
				f.write(frag_log)
		
		def get_header_reader(self, entry, ind=0):
			p = entry.pointers[ind]
			header_reader = self.header_entries[p.header_index].data	
			header_reader.seek(p.data_offset)
			return header_reader, p.data_size
		
		def get_header_data(self, entry, ind=0):
			"""Get the data for a fragment or sized str entry from the right header data IO object """
			header_reader, data_size = self.get_header_reader(entry, ind)
			return header_reader.read(data_size)
				
		def get_from(self, cls, stream):
			instance = cls()
			instance.read(stream, self)
			return instance
			
		def get_at_addr(self, cls, stream, addr):
			stream.seek(addr)
			return self.get_from(cls, stream)
		
		def get_address(self, d, header_index, data_offset):
			header_index = getattr(d, header_index)
			data_offset = getattr(d, data_offset)
			header_entry = self.header_entries[header_index]
			return self.header_size + header_entry.offset + data_offset
				
		def get_frag_after_terminator(self, l, h_types, initpos, terminator=24):
			"""Returns entries of l matching each type tuple in t that have not been processed.
			t: tuple of (x,y) tuples for each self.fragments header types"""
			out = []
			# print("looking for",h_types)
			for f in l:
				if f.pointers[0].address >= initpos:
					# can't add self.fragments that have already been added elsewhere
					if f.done:
						continue
					# print((f.type_0, f.type_1))
					if h_types == (f.pointers[0].type, f.pointers[1].type):
						# print(f.data_offset_0,"  ",initpos)
						f.done = True
						out.append(f)
						if f.pointers[0].data_size == terminator:
							break
			else:
				raise AttributeError(f"Could not find a terminator fragment matching header types {h_types} and pointer[0].size {terminator}" )
			return out
		
		def get_frag_after(self, l, t, initpos):
			"""Returns entries of l matching each type tuple in t that have not been processed.
			t: tuple of (x,y) tuples for each self.fragments header types"""
			out = []
			for h_types in t:
				# print("looking for",h_types)
				for f in l:
					if f.pointers[0].address >= initpos:
						# can't add self.fragments that have already been added elsewhere
						if f.done:
							continue
						# print((f.type_0, f.type_1))
						if h_types == (f.pointers[0].type, f.pointers[1].type):
							# print(f.data_offset_0,"  ",initpos)
							f.done = True
							out.append(f)
							break
				else:
					raise AttributeError("Could not find a fragment matching header types "+str(h_types) )
			return list(reversed(out))
		
		def get_frag2(self, l, t):
			"""Returns entries of l matching each type tuple in t that have not been processed.
			t: tuple of (x,y) tuples for each self.fragments header types"""
			out = []
			for h_types in t:
				# print("looking for",h_types)
				for f in l:
					#if abs(f.data_offset_0-initpos) <= 1000:
					# can't add self.fragments that have already been added elsewhere
					if f.done == False:
						continue
					# print((f.type_0, f.type_1))
					if h_types == (f.pointers[0].type, f.pointers[1].type):
						# print(f.data_offset_0)
						f.done = False
						out.append(f)
						break
				else:
					raise AttributeError("Could not find a fragment matching header types "+str(h_types) )
			return out
		
		def get_mdl2frag(self, l, t):
			"""Returns entries of l matching each type tuple in t that have not been processed.
			t: tuple of (x,y) tuples for each self.fragments header types"""
			out = []
			for h_types in t:
				# print("looking for",h_types)
				for f in l:
					# can't add self.fragments that have already been added elsewhere
					if f.done:
						continue
					# print((f.type_0, f.type_1))
					if h_types == (f.pointers[0].type, f.pointers[1].type):
						f.done = True
						out.append(f)
						# print(f.data_offset_0)
						break
				else:
					raise AttributeError("Could not find a fragment matching header types "+str(h_types) )
			return out
            
		def get_model_data_frags(self, l, t):
			"""Returns entries of l matching each type tuple in t that have not been processed.
			t: tuple of (x,y) tuples for each self.fragments header types"""
			out = []
			for h_types in t:
				# print("looking for",h_types)
				for f in l:
					if f.lod == False:
						continue
					# print((f.type_0, f.type_1))
					else:
						f.lod = False
						out.append(f)
						break
				else:
					raise AttributeError("Could not find a fragment matching header types "+str(h_types) )
			return out
		
			
		def find_entry(self, l, file_hash, ext_hash):
			""" returns entry from list l whose file hash matches hash, or none"""
			# try to find it
			for entry in l:
				if entry.file_hash == file_hash and entry.ext_hash == ext_hash:
					return entry
		
		
