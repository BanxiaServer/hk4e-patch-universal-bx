use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use regex::Regex;

use serde::Deserialize;
use super::{MhyContext, MhyModule, ModuleType};
use crate::marshal;
use anyhow::{anyhow, Result};
use ilhook::x64::Registers;
use crate::util;

const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "55 41 56 56 57 53 48 81 EC ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 89 D6 48 89 CF 48 8B 0D ?? ?? ?? ??";
const BROWSER_LOAD_URL: &str = "41 B0 01 E9 08 00 00 00 0F 1F 84 00 00 00 00 00 56 57";
const BROWSER_LOAD_URL_OFFSET: usize = 0x10;

const CONFIG_FILE_NAME: &str = "config.toml";
const CONFIG_EXAMPLE_FILE_NAME: &str = "configExample.toml";

// 嵌入 configExample.toml 文件内容
const CONFIG_EXAMPLE_CONTENT: &str = include_str!("../../configExample.toml");

// 目标服务器地址
static mut NEW_URL: Option<String> = None;

pub struct Http;

#[derive(Deserialize)]
struct Config {
    server: ServerConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    url: String,
}

fn ensure_config_file_exists() -> Result<()> {
    let config_path = Path::new(CONFIG_FILE_NAME);
    if !config_path.exists() {
        let example_path = Path::new(CONFIG_EXAMPLE_FILE_NAME);
        if !example_path.exists() {
            // 如果 configExample.toml 也不存在，则创建它
            fs::write(example_path, CONFIG_EXAMPLE_CONTENT)
                .map_err(|e| anyhow!("无法创建示例配置文件 {}: {}", CONFIG_EXAMPLE_FILE_NAME, e))?;
        }
        // 复制 configExample.toml 为 config.toml
        fs::copy(example_path, config_path)
            .map_err(|e| anyhow!("无法复制配置文件 {}: {}", CONFIG_EXAMPLE_FILE_NAME, e))?;
        println!("已创建配置文件 {}", CONFIG_FILE_NAME);
    }
    Ok(())
}

fn read_config() -> Result<String> {
    ensure_config_file_exists()?;

    let path = Path::new(CONFIG_FILE_NAME);
    let mut file = File::open(path).map_err(|e| anyhow!("无法打开配置文件: {}, 原因:{}", CONFIG_FILE_NAME, e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| anyhow!("读取配置文件失败: {}, 原因:{}", CONFIG_FILE_NAME, e))?;

    if contents.trim().is_empty() {
        return Err(anyhow!("配置文件为空"));
    }

    let config: Config = toml::from_str(&contents).map_err(|e| anyhow!("无法解析配置文件: {}, 原因:{}", CONFIG_FILE_NAME, e))?;

    if config.server.url.is_empty() {
        return Err(anyhow!("配置文件: {} 中的 URL 为空", CONFIG_FILE_NAME));
    }

    // 从 URL 末尾修剪非字母数字字符
    Ok(config.server.url.trim_end_matches(|c: char| !c.is_alphanumeric()).to_string())
}

impl MhyModule for MhyContext<Http> {
    unsafe fn init(&mut self) -> Result<()> {
        match read_config() {
            Ok(new_url) => {
                NEW_URL = Some(new_url);
            }
            Err(e) => {
                eprintln!("读取配置文件: {} 时出错, 请阅读 {} 或将其内容复制到 {}\n原因:{}", CONFIG_FILE_NAME, CONFIG_EXAMPLE_FILE_NAME, CONFIG_FILE_NAME, e);
                return Err(e);
            }
        }

        let web_request_utils_make_initial_url = util::pattern_scan_il2cpp(self.assembly_name, WEB_REQUEST_UTILS_MAKE_INITIAL_URL);
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("web_request_utils_make_initial_url: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_make_initial_url,
            )?;
        } else {
            println!("Failed to find web_request_utils_make_initial_url");
        }

        let browser_load_url = util::pattern_scan_il2cpp(self.assembly_name, BROWSER_LOAD_URL);
        if let Some(addr) = browser_load_url {
            let addr_offset = addr as usize + BROWSER_LOAD_URL_OFFSET;
            println!("browser_load_url: {:x}", addr_offset);
            self.interceptor.attach(
                addr_offset,
                on_browser_load_url,
            )?;
        } else {
            println!("Failed to find browser_load_url");
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        NEW_URL = None;
        Ok(())
    }

    fn get_module_type(&self) -> ModuleType {
        ModuleType::Http
    }
}

unsafe extern "win64" fn on_make_initial_url(reg: *mut Registers, _: usize) {
    let cur_new_url = NEW_URL.as_ref().expect("NEW_URL not set");
    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u16;

    let slice = std::slice::from_raw_parts(str_ptr, str_length as usize);
    let url: String = slice.iter().cloned().map(|u| char::from_u32(u as u32).unwrap()).collect();

    let mut new_url = cur_new_url.to_string();
    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    if !url.contains("/query_cur_region") {
        println!("Redirect: {url} -> {new_url}");
        (*reg).rcx =
            marshal::ptr_to_string_ansi(CString::new(new_url.as_str()).unwrap().as_c_str()) as u64;
    }
}

unsafe extern "win64" fn on_browser_load_url(reg: *mut Registers, _: usize) {
    let cur_new_url = NEW_URL.as_ref().expect("NEW_URL not set");
    let str_length = *((*reg).rdx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rdx.wrapping_add(20) as *const u16;

    let slice = std::slice::from_raw_parts(str_ptr, str_length as usize);
    let url: String = slice.iter().cloned().map(|u| char::from_u32(u as u32).unwrap()).collect();

    let mut new_url = cur_new_url.to_string();
    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    println!("Browser::LoadURL: {url} -> {new_url}");

    (*reg).rdx =
        marshal::ptr_to_string_ansi(CString::new(new_url.as_str()).unwrap().as_c_str()) as u64;
}
