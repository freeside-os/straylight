mod build;
mod install;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build" => {
            if args.len() >= 4 && args[2] == "--group" {
                match build::build_group(&args[3]) {
                    Ok(_) => {
                        println!("Group build completed successfully!");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                let package_dir = std::path::Path::new(&args[2]);
                match build::build_package(package_dir) {
                    Ok(_) => {
                        println!("Build completed successfully!");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        "install-pkg" => {
            match install::install_package(&args[2]) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  straylight build <path-to-package-dir | name>");
    eprintln!("  straylight build --group <group-name>");
    eprintln!("  straylight install-pkg <path-to-pkg.tar.gz | name-version>");
}
