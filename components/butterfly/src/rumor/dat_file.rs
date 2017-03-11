// Copyright (c) 2017 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::mem;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use protobuf::{self, Message};

use error::{Result, Error};
use member::{Health, Member, MemberList};
use message;
use rumor::{Election, ElectionUpdate, Rumor, RumorStore, Service, ServiceConfig, ServiceFile};
use server::Server;

/// A versioned binary file containing rumors exchanged by the butterfly server which have
/// been periodically persisted to disk.
///
/// The contents of the DatFile can be used to rebuild and resume a butterfly server connection
/// if it has been destroyed or lost.
///
/// * Header Version - 1 byte
/// * Header Body - Variable bytes - see Header
/// * Rumors - Variable bytes
#[derive(Debug)]
pub struct DatFile {
    header: Header,
    path: PathBuf,
}

impl DatFile {
    fn init(file: &mut File) -> io::Result<usize> {
        let mut total = 0;
        let header_reserve = vec![0; mem::size_of::<Header>()];
        // JW TODO: write actual version
        total += file.write(&[1]).expect("verwrite");
        total += file.write(&header_reserve).expect("reserve");
        Ok(total)
    }

    pub fn new<T: AsRef<Path>>(member_id: &str, data_path: T) -> Self {
        DatFile {
            path: data_path.as_ref().join(format!("{}.rst", member_id)),
            header: Header::default(),
        }
    }

    fn write_header(file: &mut File, header: &Header) -> io::Result<usize> {
        let bytes = header.write_to_bytes().unwrap();
        let total = file.write(&bytes)?;
        Ok(total)
    }

    fn write_member_list(file: &mut File, member_list: &MemberList) -> io::Result<u64> {
        let mut total = 0;
        for member in member_list.members.read().expect("Member list lock poisoned").values() {
            total += Self::write_member(file, member)?;
        }
        Ok(total)
    }

    fn write_member(file: &mut File, member: &Member) -> io::Result<u64> {
        let mut total = 0;
        let mut member_len = [0; 8];
        let bytes = member.write_to_bytes().unwrap();
        LittleEndian::write_u64(&mut member_len, bytes.len() as u64);
        total += file.write(&member_len)? as u64;
        total += file.write(&bytes)? as u64;
        Ok(total)
    }

    fn write_rumor_store<T>(file: &mut File, store: &RumorStore<T>) -> io::Result<u64>
        where T: Rumor
    {
        let mut total = 0;
        for member in store.list
            .read()
            .expect("Rumor store lock poisoned")
            .values() {
            for rumor in member.values() {
                total += Self::write_rumor(file, rumor)?;
            }
        }
        Ok(total)
    }

    fn write_rumor<T: Rumor>(file: &mut File, rumor: &T) -> io::Result<u64> {
        let mut total = 0;
        let mut rumor_len = [0; 8];
        let bytes = rumor.write_to_bytes().unwrap();
        LittleEndian::write_u64(&mut rumor_len, bytes.len() as u64);
        total += file.write(&rumor_len)? as u64;
        total += file.write(&bytes)? as u64;
        Ok(total)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_into(&mut self, server: &Server) -> Result<()> {
        let mut version = [0; 1];
        let mut rumor_size_buf = [0; 8];
        let mut rumor_buf: Vec<u8> = vec![];
        let mut file = File::open(&self.path).expect("read_into");
        file.read_exact(&mut version).expect("read-ver");
        println!("HEADER VER: {}", version[0]);
        self.header = Header::from_file(&mut file).expect("asdf");
        println!("HEADER: {:?}", self.header);

        println!("reading member rumors");
        file.seek(SeekFrom::Start(self.member_offset()));
        let mut total = 0;
        loop {
            if total >= self.header.member_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            // JW: Resizing this buffer is terrible for performance.
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = Member::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_member(rumor, Health::Suspect);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }

        println!("reading service rumors");
        total = 0;
        loop {
            if total >= self.header.service_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            // JW: Resizing this buffer is terrible for performance.
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = Service::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_service(rumor);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }

        println!("reading service_config rumors");
        total = 0;
        loop {
            if total >= self.header.service_config_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = ServiceConfig::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_service_config(rumor);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }

        println!("reading service_file rumors");
        total = 0;
        loop {
            if total >= self.header.service_file_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = ServiceFile::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_service_file(rumor);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }

        println!("reading election rumors");
        total = 0;
        loop {
            if total >= self.header.election_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = Election::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_election(rumor);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }

        println!("reading update rumors");
        total = 0;
        loop {
            if total >= self.header.update_len {
                break;
            }
            file.read_exact(&mut rumor_size_buf);
            let rumor_size = LittleEndian::read_u64(&rumor_size_buf);
            rumor_buf.resize(rumor_size as usize, 0);
            file.read_exact(&mut rumor_buf);
            let rumor = ElectionUpdate::from_bytes(&rumor_buf).expect("bad bytes");
            server.insert_update_election(rumor);
            total += rumor_size_buf.len() as u64 + rumor_size;
        }
        Ok(())
    }

    pub fn write(&self, server: &Server) -> Result<usize> {
        let tmp_path = self.path.with_extension("dat.tmp");
        {
            let mut header = Header::default();
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .expect("failure 1");
            Self::init(&mut file).expect("init");
            header.member_len = Self::write_member_list(&mut file, &server.member_list)
                .expect("f1");
            header.service_len = Self::write_rumor_store(&mut file, &server.service_store)
                .expect("failure 3");
            header.service_config_len = Self::write_rumor_store(&mut file,
                                                                &server.service_config_store)
                .expect("failure 4");
            header.service_file_len =
                Self::write_rumor_store(&mut file, &server.service_file_store).expect("failure 5");
            header.election_len = Self::write_rumor_store(&mut file, &server.election_store)
                .expect("failure 6");
            header.update_len = Self::write_rumor_store(&mut file, &server.update_store)
                .expect("failure 7");
            file.seek(SeekFrom::Start(1));
            Self::write_header(&mut file, &header).expect("wh2");
            file.flush().expect("failed to flush");
        }
        fs::rename(&tmp_path, &self.path).expect("failed move");
        Ok(0)
    }

    fn member_offset(&self) -> u64 {
        1 + mem::size_of::<Header>() as u64
    }

    fn service_offset(&self) -> u64 {
        self.member_offset() + self.header.member_len
    }

    fn service_config_offset(&self) -> u64 {
        self.service_offset() + self.header.service_len
    }

    fn service_file_offset(&self) -> u64 {
        self.service_config_offset() + self.header.service_config_len
    }

    fn election_offset(&self) -> u64 {
        self.service_file_offset() + self.header.service_file_len
    }

    fn update_offset(&self) -> u64 {
        self.election_offset() + self.header.election_len
    }
}

/// Describes contents and structure of dat file.
///
/// The information in this header is used to enable IO seeking operations on a binary dat
/// file containing rumors exchanged by the butterfly server.
#[derive(Debug, Default, PartialEq)]
pub struct Header {
    pub member_len: u64,
    pub service_len: u64,
    pub service_config_len: u64,
    pub service_file_len: u64,
    pub election_len: u64,
    pub update_len: u64,
}

impl Header {
    pub fn from_file(file: &mut File) -> Result<Self> {
        let mut bytes = vec![0; mem::size_of::<Self>()];
        file.read_exact(&mut bytes).expect("header from bytes");
        Ok(Self::from_bytes(&bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Header {
            member_len: LittleEndian::read_u64(&bytes[0..8]),
            service_len: LittleEndian::read_u64(&bytes[8..16]),
            service_config_len: LittleEndian::read_u64(&bytes[16..24]),
            service_file_len: LittleEndian::read_u64(&bytes[24..32]),
            election_len: LittleEndian::read_u64(&bytes[32..40]),
            update_len: LittleEndian::read_u64(&bytes[40..48]),
        }
    }

    pub fn write_to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; mem::size_of::<Self>()];
        LittleEndian::write_u64(&mut bytes[0..8], self.member_len);
        LittleEndian::write_u64(&mut bytes[8..16], self.service_len);
        LittleEndian::write_u64(&mut bytes[16..24], self.service_config_len);
        LittleEndian::write_u64(&mut bytes[24..32], self.service_file_len);
        LittleEndian::write_u64(&mut bytes[32..40], self.election_len);
        LittleEndian::write_u64(&mut bytes[40..48], self.update_len);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::mem;

    use rand;
    use super::*;

    #[test]
    fn read_write_header() {
        let mut original = Header::default();
        original.service_len = rand::random::<u64>();
        original.service_config_len = rand::random::<u64>();
        original.service_file_len = rand::random::<u64>();
        original.election_len = rand::random::<u64>();
        original.update_len = rand::random::<u64>();
        let bytes = original.write_to_bytes().unwrap();
        let restored = Header::from_bytes(&bytes);
        assert_eq!(bytes.len(), mem::size_of::<Header>());
        assert_eq!(original, restored);
    }
}
