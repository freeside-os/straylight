mod build;
mod install;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let keep_sandbox = args.iter().any(|arg| arg == "--keep-sandbox");
    args.retain(|arg| arg != "--keep-sandbox");

    if args.len() < 3 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build" => {
            if args.len() == 4 && args[2] == "--group" {
                match build::build_group(&args[3], keep_sandbox) {
                    Ok(_) => {
                        println!("Group build completed successfully!");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else if args.len() == 4 && args[2] == "--pkg" {
                match build::build_package(&args[3], keep_sandbox) {
                    Ok(_) => {
                        println!("Build completed successfully!");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                print_usage();
                std::process::exit(1);
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
    eprintln!("  straylight build --pkg <package-name> [--keep-sandbox]");
    eprintln!("  straylight build --group <group-name> [--keep-sandbox]");
    eprintln!("  straylight install-pkg <path-to-pkg.tar.gz | name-version>");
}
