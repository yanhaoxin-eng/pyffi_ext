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
import math
import time
import numpy as np

import pyffi.object_models.xml
import pyffi.object_models.common
import pyffi.object_models

def findall(p, s):
	'''Yields all the positions of
	the pattern p in the string s.'''
	i = s.find(p)
	while i != -1:
		yield i
		i = s.find(p, i+1)
		
class Ms2Format(pyffi.object_models.xml.FileFormat):
	"""This class implements the Ms2 format."""
	xml_file_name = 'ms2.xml'
	# where to look for ms2.xml and in what order:
	# MS2XMLPATH env var, or Ms2Format module directory
	xml_file_path = [os.getenv('MS2XMLPATH'), os.path.dirname(__file__)]
	# file name regular expression match
	RE_FILENAME = re.compile(r'^.*\.ms2$', re.IGNORECASE)
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
	SizedString = pyffi.object_models.common.SizedString
	ZString = pyffi.object_models.common.ZString
	
	class Matrix44:
		def as_list(self):
			"""Return matrix as 4x4 list."""
			return [
				[self.m_11, self.m_12, self.m_13, self.m_14],
				[self.m_21, self.m_22, self.m_23, self.m_24],
				[self.m_31, self.m_32, self.m_33, self.m_34],
				[self.m_41, self.m_42, self.m_43, self.m_44]
				]

		def as_tuple(self):
			"""Return matrix as 4x4 tuple."""
			return (
				(self.m_11, self.m_12, self.m_13, self.m_14),
				(self.m_21, self.m_22, self.m_23, self.m_24),
				(self.m_31, self.m_32, self.m_33, self.m_34),
				(self.m_41, self.m_42, self.m_43, self.m_44)
				)

		def set_rows(self, row0, row1, row2, row3):
			"""Set matrix from rows."""
			self.m_11, self.m_12, self.m_13, self.m_14 = row0
			self.m_21, self.m_22, self.m_23, self.m_24 = row1
			self.m_31, self.m_32, self.m_33, self.m_34 = row2
			self.m_41, self.m_42, self.m_43, self.m_44 = row3

	class Data(pyffi.object_models.FileFormat.Data):
		"""A class to contain the actual Ms2 data."""
		def __init__(self):
			self.version = 0
			self.mdl2_header = Ms2Format.Mdl2InfoHeader()
			self.ms2_header = Ms2Format.Ms2InfoHeader()
		
		def inspect_quick(self, stream):
			"""Quickly checks if stream contains DDS data, and gets the
			version, by looking at the first 8 bytes.

			:param stream: The stream to inspect.
			:type stream: file
			"""
			pos = stream.tell()
			try:
				magic, self.version, self.user_version = struct.unpack("<4s2I", stream.read(12))
				print("magic, self.version, self.user_version",magic, self.version, self.user_version)
			finally:
				stream.seek(pos)

		# overriding pyffi.object_models.FileFormat.Data methods

		def inspect(self, stream):
			"""Quickly checks if stream contains DDS data, and reads the
			header.

			:param stream: The stream to inspect.
			:type stream: file
			"""
			pos = stream.tell()
			try:
				self.inspect_quick(stream)
				self.mdl2_header.read(stream, data=self)
			finally:
				stream.seek(pos)
		
		def read(self, stream, verbose=0, file="", quick=False, map_bytes=False):
			"""Read a dds file.

			:param stream: The stream from which to read.
			:type stream: ``file``
			"""
			start_time = time.time()
			# store file name for later
			if file:
				self.file = file
				self.dir, self.basename = os.path.split(file)
				self.file_no_ext = os.path.splitext(self.file)[0]
			self.inspect_quick(stream)
			
			# read the file
			self.mdl2_header.read(stream, data=self)
			# print(self.mdl2_header)
			
			# extra stuff
			self.bone_info = None
			base = self.mdl2_header.model_info.pack_offset
			# print("pack base",base)
		
			self.ms2_path = os.path.join(self.dir, self.mdl2_header.name.decode())
			with open(self.ms2_path, "rb") as ms2_stream:
				self.ms2_header.read(ms2_stream, data=self)
				# print(self.ms2_header)
				self.eoh = ms2_stream.tell()
				# first get all bytes of the whole bone infos block
				bone_info_bytes = ms2_stream.read(self.ms2_header.bone_info_size)
				# find the start of each using this identifier
				bone_info_marker = bytes.fromhex("FF FF 00 00 00 00 00 00 04")
				# there's 8 bytes before this
				bone_info_starts = list( x-8 for x in findall(bone_info_marker, bone_info_bytes) )
				print("bone_info_starts",bone_info_starts)

				if bone_info_starts:
					idx = self.mdl2_header.index
					if idx >= len(bone_info_starts):
						print("reset boneinfo index")
						idx = 0
					bone_info_address = self.eoh + bone_info_starts[idx]
					print("using bone info {} at address {}".format(idx, bone_info_address) )
					ms2_stream.seek(bone_info_address)
					self.bone_info = Ms2Format.Ms2BoneInfo()
					self.bone_info.read(ms2_stream, data=self)
					# print(self.bone_info)
					
					self.bone_names = [self.ms2_header.names[i] for i in self.bone_info.name_indices]
				else:
					print("No bone info found")
					self.bone_names = []
				ms2_stream.seek(self.eoh + self.ms2_header.bone_info_size)
				# get the starting position of buffer #2, vertex & face array
				self.start_buffer2 = ms2_stream.tell()
				print("vert array start", self.start_buffer2 )
				print("tri array start", self.start_buffer2 + self.ms2_header.buffer_info.vertexdatasize)
				
				if not quick:
					for model in self.mdl2_header.models:
						model.populate(self, ms2_stream, self.start_buffer2, self.bone_names, base)

				if map_bytes:
					for model in self.mdl2_header.models:
						model.read_bytes_map(self.start_buffer2, ms2_stream)
					return

			# set material links
			for mat_1 in self.mdl2_header.materials_1:
				try:
					name = self.ms2_header.names[mat_1.material_index]
					model = self.mdl2_header.models[mat_1.model_index]
					model.material = name
				except:
					print("Couldn't match material -bug?")
			# todo - doesn't seem to be correct, at least not for JWE dinos
			self.mdl2_header.lod_names = [self.ms2_header.names[lod.strznameidx] for lod in self.mdl2_header.lods]
			print("lod_names", self.mdl2_header.lod_names)
			print(f"Finished reading in {time.time()-start_time:.2f} seconds!")

		def write(self, stream, verbose=0, file=""):
			"""Write a dds file.

			:param stream: The stream to which to write.
			:type stream: ``file``
			:param verbose: The level of verbosity.
			:type verbose: ``int``
			"""
				
			exp = "export"
			exp_dir = os.path.join(self.dir, exp)
			os.makedirs(exp_dir, exist_ok=True)
			print("Writing verts and tris to temporary buffer")
			# write each model's vert & tri block to a temporary buffer
			temp_vert_writer = io.BytesIO()
			temp_tris_writer = io.BytesIO()
			vert_offset = 0
			tris_offset = 0
			for i, model in enumerate(self.mdl2_header.models):
				model.write_verts(temp_vert_writer, data=self)
				model.write_tris(temp_tris_writer, data=self)
				print("vert_offset",vert_offset)
				print("tris_offset",tris_offset)
				
				# update ModelData struct
				model.vertex_offset = vert_offset
				model.tri_offset = tris_offset
				model.vertex_count = len(model.verts)
				model.tri_index_count = len(model.tri_indices)
				
				# offsets for the next model
				vert_offset = temp_vert_writer.tell()
				tris_offset = temp_tris_writer.tell()
			
			# update lod fragment
			print("update lod fragment")
			for lod in self.mdl2_header.lods:
				# print(lod)
				lod_models = tuple(model for model in self.mdl2_header.models[lod.first_model_index:lod.last_model_index])
				# print(lod_models)
				lod.vertex_count = sum(model.vertex_count for model in lod_models)
				lod.tri_index_count = sum(model.tri_index_count for model in lod_models)
				print("lod.vertex_count",lod.vertex_count)
				print("lod.tri_index_count",lod.tri_index_count)
			print("Writing final output")
			# get original header and buffers 0 & 1
			input_ms2_name = self.mdl2_header.name.decode()
			self.ms2_path = os.path.join(self.dir, input_ms2_name)
			with open(self.ms2_path, "rb") as ms2_stream:
				self.ms2_header.read(ms2_stream, data=self)
				buffer_1 = ms2_stream.read(self.ms2_header.bone_info_size)
			
			# get bytes from IO object
			vert_bytes = temp_vert_writer.getvalue()
			tris_bytes = temp_tris_writer.getvalue()
			
			# modify buffer size
			self.ms2_header.buffer_info.vertexdatasize = len(vert_bytes)
			self.ms2_header.buffer_info.facesdatasize = len(tris_bytes)
			
			# create name of output ms2
			# temp_ms2_name = input_ms2_name.rsplit(".",1)[0]+"_export.ms2"
			ms2_path = os.path.join(exp_dir, input_ms2_name)
			
			# write output ms2
			with open(ms2_path, "wb") as f:
				self.ms2_header.write(f, data=self)
				f.write(buffer_1)
				f.write(vert_bytes)
				f.write(tris_bytes)
				
			# set new ms2 name to mdl2 header
			# self.mdl2_header.name = temp_ms2_name.encode()
			
			# write final mdl2
			dir, mdl2_name = os.path.split(file)
			mdl2_path = os.path.join(exp_dir, mdl2_name)
			with open(mdl2_path, "wb") as f:
				self.mdl2_header.write(f, data=self)
	
	class ModelData:
		
		# def __init__(self, **kwargs):
			# BasicBase.__init__(self, **kwargs)
			# self.set_value(False)

		def read_bytes_map(self,  start_buffer2, stream):
			"""Used to document byte usage of different vertex formats"""
			# read a vertices of this model
			stream.seek(start_buffer2 + self.vertex_offset)
			# read the packed data
			data = np.fromfile(stream, dtype=np.ubyte, count=self.size_of_vertex * self.vertex_count)
			data = data.reshape((self.vertex_count, self.size_of_vertex ))
			self.bytes_map = np.max(data, axis=0)
			if self.size_of_vertex != 48:
				raise AttributeError(f"size_of_vertex != 48: size_of_vertex {self.size_of_vertex}, flag {self.flag}", )
			# print(self.size_of_vertex, self.flag, self.bytes_map)

		def init_arrays(self, count, dt):
			self.vertex_count = count
			self.vertices = np.empty( (self.vertex_count, 3), np.float32 )
			self.normals = np.empty( (self.vertex_count, 3), np.float32 )
			self.tangents = np.empty( (self.vertex_count, 3), np.float32 )
			try:
				uv_shape = dt["uvs"].shape
				self.uvs = np.empty( (self.vertex_count, *uv_shape), np.float32 )
			except:
				self.uvs = None
			try:
				colors_shape = dt["colors"].shape
				self.colors = np.empty( (self.vertex_count, *colors_shape), np.float32 )
			except:
				self.colors = None
			self.weights = []

		def get_dtype(self):
			# basic shared stuff
			dt = [
				("pos", np.uint64),
				("normal", np.ubyte, (3,)),
				("unk", np.ubyte),
				("tangent", np.ubyte, (3,)),
				("bone index", np.ubyte),
				]
			# uv variations
			if self.flag == 529:
				dt.extend([
					("uvs", np.ushort, (1, 2)),
					("zeros0", np.int32, (3,))
				])
			elif self.flag in (885, 565):
				dt.extend([
					("uvs", np.ushort, (3, 2)),
					("zeros0", np.int32, (1,))
				])
			elif self.flag == 533:
				dt.extend([
					("uvs", np.ushort, (1, 2)),
					("zeros0", np.int32, (1,)),
					("colors", np.ubyte, (1, 4)),
					("zeros2", np.int32, (1,))
				])
			elif self.flag == 513:
				dt.extend([
					("uvs", np.ushort, (1, 2)),
					("colors", np.ubyte, (1, 4)),
					("zeros2", np.uint64, (3,))
				])
			# ???
			elif self.flag == 512:
				dt.extend([
					("uvs", np.ushort, (1, 2)),
					("colors", np.ubyte, (7, 4)),
				])
			# ???
			elif self.flag == 517:
				dt.extend([
					("uvs", np.ushort, (1, 2)),
					("colors", np.ubyte, (7, 4)),
				])

			# bone weights
			if self.flag in (529, 533, 885, 565):
				dt.extend([
					("bone ids", np.ubyte, (4,)),
					("bone weights", np.ubyte, (4,)),
					("zeros1", np.uint64)
				])
			rt_dt = np.dtype(dt)
			if rt_dt.itemsize != self.size_of_vertex:
				raise AttributeError(f"Vertex size for flag {self.flag} is wrong! Collected {rt_dt.itemsize}, got {self.size_of_vertex}")
			return rt_dt

		def read_verts(self, stream, data):
			# read a vertices of this model
			stream.seek(self.start_buffer2 + self.vertex_offset)
			# get dtype according to which the vertices are packed
			dt = self.get_dtype()
			# read the packed data
			data = np.fromfile(stream, dtype=dt, count=self.vertex_count)
			# create arrays for the unpacked data
			self.init_arrays(self.vertex_count, dt)
			# first cast to the float uvs array so unpacking doesn't use int division
			if self.uvs is not None:
				self.uvs[:] = data[:]["uvs"]
				# unpack uvs
				self.uvs = (self.uvs - 32768) / 2048
			if self.colors is not None:
				# first cast to the float colors array so unpacking doesn't use int division
				self.colors[:] = data[:]["colors"]
				self.colors /= 255
			for i in range(self.vertex_count):
				self.vertices[i] = self.position(data[i]["pos"])
				self.normals[i] = self.unpack_ubyte_vector(data[i]["normal"])
				self.tangents[i] = self.unpack_ubyte_vector(data[i]["tangent"])

				# stores all (bonename, weight) pairs of this vertex
				vert_w = []
				if self.bone_names:
					if "bone ids" in dt.fields:
						weights = self.get_weights(data[i]["bone ids"], data[i]["bone weights"])
						vert_w = [(self.bone_names[bone_i], w) for bone_i, w in weights]
					# fallback: skin parition
					if not vert_w:
						vert_w = [(self.bone_names[data[i]["bone index"]], 1), ]

				# create fur length vgroup
				if self.flag == 885:
					vert_w.append(("fur_length", self.uvs[i][1][0]))

				# the unknown 0, 128 byte
				vert_w.append(("unk0", data[i]["unk"]/255))
				self.weights.append(vert_w)

		@staticmethod
		def unpack_ushort_vector(vec):
			return (vec - 32768) / 2048
			# return (vec - 32768) / 2048

		@staticmethod
		def unpack_ubyte_vector(vec):
			vec = (vec - 128) / 128
			# swizzle to avoid a matrix multiplication for global axis correction
			return -vec[0], -vec[2], vec[1]

		@staticmethod
		def get_weights(bone_ids, bone_weights):
			return [(i, w / 255) for i, w in zip(bone_ids, bone_weights) if w > 0]

		def position(self, input):
			"""Unpacks and returns the self.raw_pos uint64"""
			# print("\nunpacking")
			# correct for size according to base, relative to 512
			input = int(input)
			scale = self.base / 512 / 2048
			# input = self.raw_pos
			output = []
			# print("inp",bin(input))
			for i in range(3):
				# print("\nnew coord")
				# grab the last 20 bits with bitand
				# bit representation: 0b11111111111111111111
				twenty_bits = input & 0xFFFFF
				# print("input", bin(input))
				# print("twenty_bits = input & 0xFFFFF ", bin(twenty_bits), twenty_bits)
				input >>= 20
				# print("input >>= 20", bin(input))
				# print("1",bin(1))
				# get the rightmost bit
				rightmost_bit = input & 1
				# print("rightmost_bit = input & 1",bin(rightmost_bit))
				# print(rightmost_bit, twenty_bits)
				if not rightmost_bit:
				# when doing this, the output mesh is fine for coords that don't exceed approximately 0.25
				# if True:
					# rightmost bit was 0
					# print("rightmost_bit == 0")
					# bit representation: 0b100000000000000000000
					twenty_bits -= 0x100000
				# print("final int", twenty_bits)
				o = (twenty_bits + self.base) * scale
				output.append(o)
				# shift to skip the sign bit
				input >>= 1
			# the inidividual coordinates
			x,y,z = output
			# swizzle to avoid a matrix multiplication for global axis correction
			return (-x,-z,y)

		def write_verts(self, stream, data):
			for vert in self.verts:
				vert.write(stream, data)
			
		def read_tris(self, stream, data):
			# read all tri indices for this model
			stream.seek( self.start_buffer2 + data.ms2_header.buffer_info.vertexdatasize + self.tri_offset )
			# print("tris offset",stream.tell())
			# read all tri indices for this model segment
			self.tri_indices = list( struct.unpack( str(self.tri_index_count)+"H", stream.read( self.tri_index_count*2 ) ) )
		
		def write_tris(self, stream, data):
			stream.write( struct.pack( str(len(self.tri_indices))+"H", *self.tri_indices ) )
		
		@property
		def lod_index(self,):
			try:
				lod_i = int(math.log2(self.poweroftwo))
			except:
				lod_i = 0
				print("EXCEPTION: math domain for lod",self.poweroftwo)
			return lod_i
			
		@lod_index.setter
		def lod_index(self, lod_i):
			self.poweroftwo = int(math.pow(2, lod_i))
		
		@property
		def tris(self,):
			# create non-overlapping tris
			# reverse to account for the flipped normals from mirroring in blender
			return [(self.tri_indices[i+2], self.tri_indices[i+1], self.tri_indices[i]) for i in range(0, len(self.tri_indices), 3)]
			
		@tris.setter
		def tris(self, b_tris):
			# clear tri array
			self.tri_indices = []
			for tri in b_tris:
				# reverse to account for the flipped normals from mirroring in blender
				self.tri_indices.extend( reversed(tri) )
			
			
		def populate(self, data, ms2_stream, start_buffer2, bone_names = [], base = 512):
			self.start_buffer2 = start_buffer2
			self.data = data
			self.base = base
			self.bone_names = bone_names
			
			# create data lists for this model
			self.verts = []
			self.vertices = []
			self.normals = []
			self.tangents = []
			# self.uv_layers = ( [], [], [], [] )
			self.colors = ( [], [] )
			self.weights = []
			self.read_verts(ms2_stream, self.data)
			self.read_tris(ms2_stream, self.data)
			
		
			
	class PackedVert:
		base = 512
		# def __init__(self, **kwargs):
			# BasicBase.__init__(self, **kwargs)
			# self.set_value(False)
		
		
		def unpack_ushort_vector(self, vec):
			return [ (coord - 32768) / 2048 for coord in (vec.u, vec.v) ]
			
		def pack_ushort_vector(self, vec):
			return [ min(int(round(coord * 2048 + 32768)), 65535) for coord in vec]
			
		def unpack_ubyte_vector(self, vec):
			vec = (vec.x, vec.y, vec.z)
			vec = [(x-128)/128 for x in vec]
			# swizzle to avoid a matrix multiplication for global axis correction
			return -vec[0], -vec[2], vec[1]
			
		def pack_ubyte_vector(self, vec):
			# swizzle to avoid a matrix multiplication for global axis correction
			vec = (-vec[0], vec[2], -vec[1])
			return [min(int(round(x*128+128)), 255) for x in vec]
		
		@property
		def position(self):
			"""Unpacks and returns the self.raw_pos uint64"""
			# print("\nunpacking")
			# correct for size according to base, relative to 512
			scale = self.base / 512 / 2048
			input = self.raw_pos
			output = []
			# print("inp",bin(input))
			for i in range(3):
				# print("\nnew coord")
				# grab the last 20 bits with bitand
				# bit representation: 0b11111111111111111111
				twenty_bits = input & 0xFFFFF
				# print("input", bin(input))
				# print("twenty_bits = input & 0xFFFFF ", bin(twenty_bits), twenty_bits)
				input >>= 20
				# print("input >>= 20", bin(input))
				# print("1",bin(1))
				# get the rightmost bit
				rightmost_bit = input & 1
				# print("rightmost_bit = input & 1",bin(rightmost_bit))
				# print(rightmost_bit, twenty_bits)
				if not rightmost_bit:
				# when doing this, the output mesh is fine for coords that don't exceed approximately 0.25
				# if True:
					# rightmost bit was 0
					# print("rightmost_bit == 0")
					# bit representation: 0b100000000000000000000
					twenty_bits -= 0x100000
				# print("final int", twenty_bits)
				o = (twenty_bits + self.base) * scale
				output.append(o)
				# shift to skip the sign bit
				input >>= 1
			# the inidividual coordinates
			x,y,z = output
			# swizzle to avoid a matrix multiplication for global axis correction
			return [-x,-z,y]

		@position.setter
		def position(self, vec):
			"""Packs the input into the self.raw_pos uint64"""
			# print("\npacking")
			# swizzle to avoid a matrix multiplication for global axis correction
			x,y,z = vec
			input = (-x,z,-y)
			# correct for size according to base, relative to 512
			scale = self.base / 512 / 2048
			output = 0
			for i, f in enumerate(input):
				o = int(round(f / scale - self.base))
				# print("restored int", o)
				if o < 0x100000:
					# 0b100000000000000000000
					o += 0x100000
				else:
					# set the 1 bit flag
					output |= 1 << (21*(i+1)-1)
				# print("restored int + correction", o)
				output |= o << (21*i)
				# print(bin(output))
				# print(bin(o))
			# output |= 1 << 63
			# print(bin(output))
			#print(str(struct.unpack("Q",struct.pack("d",struct.unpack("d",struct.pack("Q",output))))))
			thing=struct.unpack("<d",struct.pack("<Q",output))
			thing2 = -1.0*float(thing[0])
			thing3 = struct.unpack("<Q",struct.pack("<d",thing2))
			output= thing3[0]
			# print("out",bin(output))
			# return output
			self.raw_pos = output

		@property
		def normal(self,):
			return self.unpack_ubyte_vector(self.raw_normal)
			
		@normal.setter
		def normal(self, value):
			self.raw_normal.x, self.raw_normal.y, self.raw_normal.z = self.pack_ubyte_vector(value)
		
		@property
		def tangent(self,):
			return self.unpack_ubyte_vector(self.raw_tangent)
			
		@tangent.setter
		def tangent(self, value):
			self.raw_tangent.x, self.raw_tangent.y, self.raw_tangent.z = self.pack_ubyte_vector(value)
		
		@property
		def uvs(self,):
			return [self.unpack_ushort_vector(uv) for uv in self.raw_uvs]
		
		@uvs.setter
		def uvs(self, uv_layers):
			for uv, uv_coord in zip(self.raw_uvs, uv_layers):
				uv.u, uv.v = self.pack_ushort_vector(uv_coord)
		
		@property
		def fur_length(self,):
			return self.unpack_ushort_vector(self.raw_uvs[1])[0]
			
		@fur_length.setter
		def fur_length(self, f):
			self.raw_uvs[1].u, _ = self.pack_ushort_vector( (f, 0) )
		
		@property
		def weights(self,):
			out = []
			for i, w in zip(self.bone_ids, self.bone_weights):
				if w > 0:
					out.append( (i, w/255) )
			return out
		
		@weights.setter
		def weights(self, weights):
			assert( len(weights) == 4 )
			# assume len(w) == 4, each is a tuple of (bone index, weight) or (0, 0)
			for i, (new_i, new_w) in enumerate(weights):
				self.bone_ids[i] = new_i
				self.bone_weights[i] = min(int(round(new_w * 255)), 255)
				
		
		# # @property
		# def position(self, base):
			# """ Set this vector to values from another object that supports iteration or x,y,z properties """
			# return read_packed_vector(self.raw_pos, base)
				
		# def __iter__(self):
			# # just a convenience so we can do: x,y,z = Vector3()
			# yield self.x
			# yield self.y
			# yield self.z
