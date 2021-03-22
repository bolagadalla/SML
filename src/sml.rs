use crate::{cf::CFFile, downloader::Downloader};
use crate::ima::Instance;
use ftp::FtpStream;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::read_password;
use serde_json::*;
use std::{fs::{File, OpenOptions}, io::{self, BufReader}};
use std::io::Write;
use std::{fs, path::PathBuf};
use zip::ZipArchive;
use serde::{ Serialize, Deserialize};
use ansi_term::Color::*;

mod util;

const CHUNK_SIZE: usize = 8192;


// needed for serde json serialization
#[derive(Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub token: String,
}


pub struct Invoker {
    java: String,
    binpath: PathBuf,
    classpaths: Vec<PathBuf>,
    args: String,
    main: String,
    ccmd: Option<String>,
}

impl Invoker {
    pub fn new(jp: String, bp: PathBuf, cp: Vec<PathBuf>, a: String, mc: String) -> Invoker {
        Invoker {
            java: jp,
            binpath: bp,
            classpaths: cp,
            args: a,
            main: mc,
            ccmd: None,
        }
    }

    pub fn gen_invocation(&mut self) {
        let mut cmd: String = self.java.clone();
        cmd.push_str(format!(" -Djava.library.path=\"{}\" ", self.binpath.display()).as_str());

        // classpaths
        cmd.push_str(" -cp ");
        for cp in self.classpaths.clone() {
            let cp_str = format!("\"{}\":", cp.display());
            cmd.push_str(cp_str.as_str());
        }

        // main class
        cmd.push_str(format!(" {} {}", self.main, self.args).as_str());

        self.ccmd = Some(cmd);
    }

    pub fn display_invocation(&self) -> () {
        println!("{}", self.ccmd.clone().unwrap());
    }

    pub fn invoke(&self) -> Result<()> {
        // make sure command is not empty
        if self.ccmd.is_none() {}

        Ok(())

        // open subprocess with command here ...
    }
}

// gets and extracts sml stage for forge version
pub fn get_stage(chosen_proj: CFFile, instance: Instance) {
    let stage_file_remote_path = format!("/shares/U/sml/{}-linux.zip", chosen_proj.version);

    let mut stage_filepath = instance.get_path();
    stage_filepath.pop();

    stage_filepath.push(format!("{}-linux.zip", chosen_proj.version));
    println!("MC Version is: {}", chosen_proj.version);

    // request server for sml stage
    let mut ftp_stream = FtpStream::connect("98.14.42.52:21").unwrap();
    let _ = ftp_stream.login("", "").unwrap();

    match fs::File::create(stage_filepath.clone()) {
        Err(e) => panic!("Couldn't create file {}", e),
        Ok(mut file) => {
            let total_size = ftp_stream
                .size(stage_file_remote_path.as_str())
                .unwrap()
                .unwrap() as u64;

            println!("Got total file size: {}", total_size);

            let pb = ProgressBar::new(total_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .progress_chars("=> "));

            let data = ftp_stream
                .simple_retr(stage_file_remote_path.as_str())
                .unwrap()
                .into_inner();

            for i in 0..data.len() / CHUNK_SIZE {
                if i != (data.len() / CHUNK_SIZE) - 1 {
                    file.write_all(&data[i * CHUNK_SIZE..(i + 1) * CHUNK_SIZE]).unwrap();
                    pb.set_position((i * CHUNK_SIZE) as u64);
                } else {
                    // write the entire last part
                    file.write_all(&data[i * CHUNK_SIZE..]).unwrap();
                    pb.set_position((i * CHUNK_SIZE) as u64);
                }
            }
            pb.finish_with_message("Finished downloading stage file");
        }
    };

    let file = fs::File::open(stage_filepath.clone()).expect("Error getting zip file");
    let mut zip = ZipArchive::new(file).unwrap();
    let extract_path = instance.get_path();
    //extract_path.pop();

    zip.extract(extract_path).expect("Error extracting forge");
    println!("Sucessfully extracted forge stage");
    println!("Cleaning up");
    fs::remove_file(stage_filepath).expect("Error deleting stage zip file");
}

pub fn get_modslist(chosen_proj: CFFile, instance: Instance) {
    let download_url = chosen_proj.get_download_url();
    let mut download_path = instance.get_path();
    download_path.push("mods/");
    if !download_path.exists() {
        fs::create_dir(download_path.clone()).expect("Error creating mods folder");
    }
    download_path.push(chosen_proj.name.clone());

    println!("Got download url {}", download_url);
    println!("Got download path {}", download_path.display());

    let mut downloader = Downloader::new();
    downloader.set_url(download_url);
    downloader.set_path(download_path.clone());
    downloader.download().expect("Error downloading modslist");

    let mut mod_dirpath = instance.get_path().clone();
    mod_dirpath.push("mods/");

    // extract zip
    let modpack_zip = fs::File::open(download_path.clone()).expect("Couldn't open modslist");
    println!("Downloaded mods list");

    println!("Extracting mods list");
    let mut zip = ZipArchive::new(modpack_zip).unwrap();
    let mut extract_path = download_path.clone();
    extract_path.pop();

    zip.extract(extract_path)
        .expect("Error extracting mods list");

    fs::remove_file(download_path.clone()).expect("Error deleting stage zip file");
}


pub fn get_cp_from_version(libpath: PathBuf, version_paths : Vec<PathBuf>) -> Vec<(String, PathBuf)> {
    let mut retvec = Vec::new();

    
    for version_fpath in version_paths {
        let file = File::open(version_fpath).unwrap();
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `User`.
        let u : serde_json::Value = serde_json::from_reader(reader).unwrap();

        let libraries = u["libraries"].as_array().unwrap();

        for lib in libraries {
            let artifact : Vec<&str> = lib["name"]
                            .as_str()
                            .unwrap()
                            .split(":")
                            .collect();

            let name = artifact[artifact.len()-2];
            let version = artifact[artifact.len()-1];
            let nv = format!("{}:{}", name, version);


            let mut path = libpath.clone();
            path.push( match lib["downloads"]["artifact"]["path"].as_str(){
                Some(val) =>  val,
                None => {
                    println!("Couldn't get library path, skipping");
                    ""
                },
            });

            let mut found_index = 0;
            let mut found_version = "";


            // this excludes forge or any other invalid lib for the check
            if lib["url"].as_str().is_none()  {
                retvec.push((nv, path));
            }else{

                // make some checks for duplicate library
                if retvec.iter().enumerate().any(|(i, v): (usize,&(String, PathBuf))|{
                    let a = &v.0;
                    let n : Vec<&str> = a.split(":").collect();
                    found_index = i;
                    found_version = n[n.len()-2];
                    name == n[n.len()-1]
                }) 
                {

                    if util::is_greater_version(version, found_version) {
                        // prev version is old
                        // remove it and put new one
                        retvec.remove(found_index);
                        retvec.push((nv, path));
                    }
                    // if prev entry has greater version, 
                    // then don't push anything
                
                }else{
                    // no duplicates found, may push
                    retvec.push((nv, path));
                }

            }
        }

    }

    retvec
}

pub fn get_libraries(libpath: PathBuf, manifests: Vec<PathBuf>) -> Result<()> {
    for manifest in manifests{

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(manifest.clone())
        .unwrap();


        let json: serde_json::Value = serde_json::from_reader(file).unwrap();
        let libraries = json["libraries"].as_array().expect("Error getting libraries.");
        let mut downloader = Downloader::new();


        for lib in libraries.iter(){

            let artifact_path = match lib["downloads"]["artifact"]["path"].as_str(){
                Some(val) => val,
                None => {
                    println!("Error getting library, skipping ...");
                    break;
                }
            };

            let mut path = libpath.clone(); 
            path.push(artifact_path);

            let download_url = match lib["downloads"]["artifact"]["url"].as_str(){
                Some(val) => val,
                None => {
                    println!("{}:{}  {}", 
                            Red.paint("Library url is missing"),
                            path.display(),
                            Yellow.paint("skipping ..."));
                    break;
                }

            };

            let artifact_sha1 = match lib["downloads"]["artifact"]["sha1"].as_str(){
                Some(hash) => hash,
                None => {
                    println!("No hash found , skipping ...");
                    break;
                }
            };

            
            // only download if url is valid
            if download_url != "" {
                downloader.set_url(download_url.to_string());
                downloader.set_path(path);
                downloader.set_sha1(artifact_sha1.to_string());
                match downloader.download() {
                    Ok(_) => {
                        //match downloader.verify_sha1(){
                        //    Some(mut is_verified) => {
                        //        while !is_verified {
                        //            println!("Invalid hash: {}",  Yellow.paint("Retrying download..."));
                        //            println!("URL: {}", download_url);
                        //            downloader.download().unwrap();
                        //            is_verified = downloader.verify_sha1().unwrap();

                        //        }

                        //        println!("{} sha1:{}", Green.paint("File verified!"),  artifact_sha1);
                        //    },
                        //    None => {
                        //        println!("{}", Red.paint("Failed to verify file"));
                        //    }
                        //};
                    },
                    Err(_) => {
                        println!("{} {}", Red.paint("Failed to download"), artifact_path);
                        continue
                    }
                };
            }
        }

    }

    Ok(())
}

pub fn get_assets(game_path: PathBuf, version_path: PathBuf) -> Result<()> {
    let version_file = File::open(version_path).unwrap();
    let version : serde_json::Value = serde_json::from_reader(version_file).unwrap();

    let url = match version["assetIndex"]["url"].as_str(){
        Some(val) => val,
        None => {
            println!("Error getting assetIndex. Skipping.");
            return Ok(());
        }
    };
    let assets_json : serde_json::Value = ureq::get(url)
                            .call()
                            .unwrap()
                            .into_json()
                            .unwrap();

    let asset_objects = assets_json["objects"].as_object().unwrap();

    for object in asset_objects{
        let hash = object.1["hash"].as_str().unwrap();
        let first_two = &hash[0..2];

        let mut save_path = game_path.clone();
        save_path.push("assets/objects/");
        save_path.push(first_two);
        save_path.push(hash);

        let download_url = format!("http://resources.download.minecraft.net/{}/{}", first_two, hash);
        println!("Got url: {}", download_url);
        let mut downloader = Downloader::new();
        downloader.set_path(save_path);
        downloader.set_url(download_url);
        downloader.download().expect("Couldn't download assets");
    }
    
    Ok(())
}

pub fn get_mods(mods_path: PathBuf){
    let mut mods_manifest_path = mods_path.clone();
    mods_manifest_path.push("manifest.json");

    let manifest_reader = File::open(mods_manifest_path).unwrap();
    let manifest : serde_json::Value = serde_json::from_reader(manifest_reader)
                                        .expect("Couldn't get mod manifest");


    let mods = manifest["files"].as_array().unwrap();
    
    for m in mods {
        let proj_id = m["projectID"].as_u64().unwrap();
        let file_id = m["fileID"].as_u64().unwrap();

        let mod_json : serde_json::Value = ureq::get(format!("https://api.cfwidget.com/{}", proj_id).as_str())
                            .call()
                            .unwrap()
                            .into_json()
                            .unwrap();
        let modfiles = match mod_json["files"].as_array(){
            Some(val) => val,
            None => {
                println!("Could not parse files list");
                continue;
            } 
        };

        for modfile in modfiles {
            // found right mod file now download it
            if modfile["id"].as_u64().unwrap() == file_id {

               let cf_file = CFFile{
                   id: file_id,
                   display: modfile["display"].as_str().unwrap().to_string(),
                   name: modfile["name"].as_str().unwrap().to_string(),
                   ftype: modfile["type"].as_str().unwrap().to_string(),
                   version: modfile["version"].as_str().unwrap().to_string()};

               let download_url = cf_file.get_download_url();
               let mut download_path = mods_path.clone();
               download_path.push(cf_file.name);
    
               // if one mod errors, then continue with the rest
               // TODO: Track and display broken files 
               let mut downloader = Downloader::new();
               downloader.set_path(download_path);
               downloader.set_url(download_url);
               match downloader.download(){
                   Ok(_) => continue,
                   Err(_) => continue,

               }
             }
        }

    }
}


pub fn handle_auth() -> Option<User> {
    let mut email: String = "".to_string();

    print!("Log in to mojang\nEmail: ");

    io::stdout().flush().unwrap();

    io::stdin().read_line(&mut email).unwrap();

    email = email.trim_end().to_string();


    let password: String = rpassword::prompt_password_stdout("Password: ").unwrap();

    let user = authorize(email.as_str(), password.as_str());

    if user.is_none() {
        handle_auth()
    }else {
        Some(user.unwrap())
    }

}

pub fn authorize(email: &str, password: &str) -> Option<User> {
    let payload = serde_json::json!(
    {
        "agent" : {
            "name": "Minecraft",
            "version" : 1
        },
        "username" : email,
        "password" : password
    });

    // send payload here
    match ureq::post("https://authserver.mojang.com/authenticate").send_json(payload) {
        Ok(userinfo) => {
            let userinfo_json: serde_json::Value =
                userinfo.into_json().expect("Error parsing auth json");

            let access_token = userinfo_json["accessToken"].clone();
            let username = userinfo_json["selectedProfile"]["name"].clone();

            Some(User {
                name: username.as_str().expect("Error parsing json").to_string(),
                token: access_token
                    .as_str()
                    .expect("Error parsing json")
                    .to_string(),
            })
        },
        Err(ureq::Error::Status(code, resp)) => {

            let err_json : serde_json::Value = resp.into_json().unwrap();
            println!("Got status {}", code);

            if code == 403 {
                return handle_auth();
            } else {
                return handle_auth();
            }
        }
        Err(_) => {
            return handle_auth();
        }
    }
}


pub fn get_fv_from_mcv(mcv: String) -> String {
    let versions_url = "https://files.minecraftforge.net/maven/net/minecraftforge/forge/promotions_slim.json"; 
    let versions_json : serde_json::Value = ureq::get(versions_url)
                                            .call()
                                            .unwrap()
                                            .into_json()
                                            .unwrap();
    let key = format!("{}-latest", mcv);
    versions_json["promos"][key]
        .as_str()
        .expect("Couldn't get forge versions list")
        .to_string()

}


pub fn get_forge_args(json: serde_json::Value) -> Option<String>{
    let mut retstr = String::new();
    // get args here
    let args = json["arguments"]["game"].as_array().unwrap();
    for arg in args{
        retstr.push(' ');
        retstr.push_str(arg.as_str().unwrap());
    } 

    Some(retstr)
}


