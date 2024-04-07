use dashmap::DashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};

const FILE_NAME: &str = "minibitcask.data";
const MERGE_FILE_NAME: &str = "minibitcask.data.merge";
const ENTRY_HEADER_SIZE: usize = 10;

#[derive(Debug)]
struct Entry {
    key: Vec<u8>,
    value: Vec<u8>,
    key_size: u32,
    value_size: u32,
    mark: u16,
}

impl Entry {
    fn new(key: Vec<u8>, value: Vec<u8>, mark: u16) -> Self {
        let key_size = key.len() as u32;
        let value_size = value.len() as u32;
        Entry {
            key,
            value,
            key_size,
            value_size,
            mark,
        }
    }

    fn size(&self) -> i64 {
        ENTRY_HEADER_SIZE as i64 + self.key_size as i64 + self.value_size as i64
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0; self.size() as usize];
        buf[0..4].copy_from_slice(&self.key_size.to_be_bytes());
        buf[4..8].copy_from_slice(&self.value_size.to_be_bytes());
        buf[8..10].copy_from_slice(&self.mark.to_be_bytes());
        buf[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + self.key.len()].copy_from_slice(&self.key);
        buf[ENTRY_HEADER_SIZE + self.key.len()..].copy_from_slice(&self.value);
        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        if buf.len() < ENTRY_HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Wrong buffer size"));
        }

        let key_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let value_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mark = u16::from_be_bytes([buf[8], buf[9]]);

        Ok(Entry {
            key: buf[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + key_size as usize].to_vec(),
            value: buf[ENTRY_HEADER_SIZE + key_size as usize..].to_vec(),
            key_size,
            value_size,
            mark,
        })
    }
}

struct DBFile {
    file: File,
    offset: i64,
    file_name: String,
}

impl DBFile {
    fn new_internal(file_name: &str) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(file_name)?;

        let metadata = file.metadata()?;
        let offset = metadata.len() as i64;

        Ok(DBFile {
            file,
            offset,
            file_name: file_name.to_string(),
        })
    }

    fn new(path: &str) -> Result<Self, std::io::Error> {
        let file_name = PathBuf::from(path).join(FILE_NAME);
        DBFile::new_internal(file_name.to_str().unwrap())
    }

    fn new_merge_db_file(path: &str) -> Result<Self, std::io::Error> {
        let file_name = PathBuf::from(path).join(MERGE_FILE_NAME);
        DBFile::new_internal(file_name.to_str().unwrap())
    }

    fn read(&mut self, offset: i64) -> Result<Entry, std::io::Error> {
        let mut buf = Vec::new();
        buf.reserve_exact(ENTRY_HEADER_SIZE);
        self.file.read_exact_at_offset(&mut buf, offset)?;
        let mut entry = Entry::decode(&buf)?;

        let mut key = vec![0; entry.key_size as usize];
        let mut value = vec![0; entry.value_size as usize];

        if entry.key_size > 0 {
            self.file
                .read_exact_at_offset(&mut key, offset + ENTRY_HEADER_SIZE as i64)?;
        }

        if entry.value_size > 0 {
            self.file.read_exact_at_offset(
                &mut value,
                offset + ENTRY_HEADER_SIZE as i64 + entry.key_size as i64,
            )?;
        }

        entry.key = key;
        entry.value = value;

        Ok(entry)
    }

    fn write(&mut self, entry: &Entry) -> Result<(), std::io::Error> {
        let encoded = entry.encode();
        self.file.write_all_at_offset(&encoded, self.offset)?;
        self.offset += entry.size();
        Ok(())
    }
}

trait FileReadAt {
    fn read_exact_at_offset(&mut self, buf: &mut [u8], offset: i64) -> Result<(), std::io::Error>;
}

trait FileWriteAt {
    fn write_all_at_offset(&mut self, buf: &[u8], offset: i64) -> Result<(), std::io::Error>;
}

impl FileReadAt for File {
    fn read_exact_at_offset(&mut self, buf: &mut [u8], offset: i64) -> Result<(), std::io::Error> {
        self.seek(std::io::SeekFrom::Start(offset as u64))?;
        self.read_exact(buf)?;
        Ok(())
    }
}

impl FileWriteAt for File {
    fn write_all_at_offset(&mut self, buf: &[u8], offset: i64) -> Result<(), std::io::Error> {
        self.seek(std::io::SeekFrom::Start(offset as u64))?;
        self.write_all(buf)?;
        Ok(())
    }
}

pub struct MiniBitcask {
    indexes: Arc<DashMap<String, i64>>,
    db_file: DBFile,
    dir_path: String,
}

impl MiniBitcask {
    pub fn open(dir_path: &str) -> Result<Self, io::Error> {
        if let Err(err) = fs::create_dir_all(dir_path) {
            if err.kind() != io::ErrorKind::AlreadyExists {
                return Err(err);
            }
        }

        let dir_abs_path = fs::canonicalize(dir_path)?;
        let db_file_path = dir_abs_path.to_string_lossy().to_string();
        let db_file = DBFile::new(&db_file_path)?;
        let indexes = Arc::new(DashMap::new());

        let mut mini_bitcask = MiniBitcask {
            indexes,
            db_file,
            dir_path: dir_abs_path.to_string_lossy().into_owned(),
        };

        mini_bitcask.load_indexes_from_file()?;
        Ok(mini_bitcask)
    }

    pub fn merge(&mut self) -> Result<(), io::Error> {
        if self.db_file.offset == 0 {
            return Ok(());
        }

        let mut valid_entries = Vec::new();
        let mut offset = 0;

        loop {
            match self.db_file.read(offset) {
                Ok(e) => {
                    let key = String::from_utf8_lossy(&e.key).to_string();
                    let indexes = Arc::clone(&self.indexes);
                    let size = e.size();
                    if let Some(off) = indexes.get(&key) {
                        if *off == offset {
                            valid_entries.push(e);
                        }
                    }
                    offset += size;
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        break;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        let mut merge_db_file = DBFile::new_merge_db_file(&self.dir_path)?;
        let merge_db_file_name = merge_db_file.file_name.clone();
        let merged_indexes = Arc::new(DashMap::new());

        for entry in valid_entries {
            let write_off = merge_db_file.offset;
            merge_db_file.write(&entry)?;

            merged_indexes.insert(String::from_utf8_lossy(&entry.key).into_owned(), write_off);
        }

        let db_file_name = self.db_file.file_name.clone();

        fs::remove_file(&db_file_name)?;
        fs::rename(&merge_db_file_name, &db_file_name)?;

        let db_file = DBFile::new(&self.dir_path)?;
        self.db_file = db_file;
        self.indexes = merged_indexes;

        Ok(())
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), io::Error> {
        if key.is_empty() {
            return Ok(());
        }

        let offset = self.db_file.offset;
        let entry = Entry::new(key.to_vec(), value.to_vec(), 0);
        self.db_file.write(&entry)?;

        self.indexes
            .insert(String::from_utf8_lossy(key).into_owned(), offset);
        Ok(())
    }

    pub fn exist(&self, key: &[u8]) -> Result<i64, io::Error> {
        if let Some(offset) = self.indexes.get(&String::from_utf8_lossy(key).into_owned()) {
            Ok(*offset)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
        }
    }

    pub fn get(&mut self, key: &[u8]) -> Result<Vec<u8>, io::Error> {
        if key.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"));
        }

        let offset = self.exist(key)?;
        let entry = self.db_file.read(offset)?;

        Ok(entry.value)
    }

    pub fn del(&mut self, key: &[u8]) -> Result<(), io::Error> {
        if key.is_empty() {
            return Ok(());
        }

        if self.exist(key).is_err() {
            return Ok(());
        }

        let entry = Entry::new(key.to_vec(), Vec::new(), 1);
        self.db_file.write(&entry)?;

        self.indexes
            .remove(&String::from_utf8_lossy(key).into_owned());
        Ok(())
    }

    fn load_indexes_from_file(&mut self) -> Result<(), io::Error> {
        let mut offset = 0;
        loop {
            match self.db_file.read(offset) {
                Ok(e) => {
                    let key = String::from_utf8_lossy(&e.key).into_owned();
                    self.indexes.insert(key, offset);
                    if e.mark == 1 {
                        self.indexes
                            .remove(&String::from_utf8_lossy(&e.key).into_owned());
                    }
                    offset += e.size();
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        break;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
