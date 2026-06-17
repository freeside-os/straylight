mod build;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "build" {
        eprintln!("Usage: straylight build <path-to-package-dir>");
        std::process::exit(1);
    }

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
