#![feature(vec_remove_item)]

use std::io::Write;
use sha2::Sha256;
use sha2::digest::Digest;
use rayon::prelude::*;
use structopt::StructOpt;

struct StringsGenerator<'a> {
    dictionary_source: &'a str,
    chars_generators: Vec<std::str::Chars<'a>>,
    current_combination: String,
}

impl<'a> StringsGenerator<'a> {
    fn new(max_length: usize, dictionary_source: &'a str) -> Self {
        let mut generator = Self {
            dictionary_source,
            chars_generators: Vec::new(),
            current_combination: String::with_capacity(max_length),
        };
        while generator.chars_generators.len() < max_length {
            generator.chars_generators.push(generator.dictionary())
        }
        return generator;
    }

    #[inline]
    fn dictionary(&self) -> std::str::Chars<'a> {
        self.dictionary_source.chars()
    }

    #[inline]
    fn increment_last_char(&mut self) -> Result<(), ()> {
        if let Some(chars) = self.chars_generators.last_mut() {
            if let Some(next_char) = chars.next() {
                self.current_combination.pop();
                self.current_combination.push(next_char);
                return Ok(());
            }
        }
        return Err(());
    }

    #[inline]
    fn increment(&mut self) -> Result<(), ()> {
        #[cfg(all(feature = "loop", not(feature = "recursion")))]
        {
            let mut tries = 0;
            // This increment the current last char before to initialize previous last again to do carry increment
            while self.increment_last_char().is_err() && self.chars_generators.len() != 0 {
                // Remove empty chars iterator and last char to carry and initialize again
                self.current_combination.pop();
                self.chars_generators.pop();
                tries += 1;
            }
            if self.chars_generators.len() == 0 {
                return Err(());
            }
            while tries != 0 {
                // Recover char length removed by failed increment before of carry
                let mut new_chars = self.dictionary();
                self.current_combination.push(new_chars.next().unwrap());
                self.chars_generators.push(new_chars);
                tries -= 1;
            }
        }
        #[cfg(feature = "recursion")]
        {
            // This increment the current last char before to initialize previous last again to do carry increment
            if self.increment_last_char().is_err() {
                // Remove empty chars iterator and last char to carry and initialize again
                self.current_combination.pop();
                self.chars_generators.pop();
                // Stop recursive carry increment if it consumed last chars iterator
                if self.chars_generators.len() == 0 {
                    return Err(());
                }
                // This increment the current last char before to initialize previous last again to do carry increment
                self.increment()?;
                // Recover char length removed by failed increment before of carry
                let mut new_chars = self.dictionary();
                self.current_combination.push(new_chars.next().unwrap());
                self.chars_generators.push(new_chars);
            }
        }
        Ok(())
    }
}

impl Iterator for StringsGenerator<'_> {
    type Item = String;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.increment().is_ok() {
            return Some(self.current_combination.clone());
        }
        None
    }
}

#[derive(StructOpt)]
struct CliOpts {
    #[structopt(short, long)]
    domains: Vec<String>,
    #[structopt(short, long)]
    hashed_emails: Vec<String>,
    #[structopt(short, long, default_value = "64")]
    max_length: u8,
    #[structopt(short, long, default_value = " -> ")]
    separator: String,
}

const DICTIONARY: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+";

fn main() {
    let options = {
        let mut options = CliOpts::from_args();
        // Emails with usernames longer than 64 chars are not valid
        if options.max_length > 64 {
            options.max_length = 64;
        }
        options
    };
    let stdout = std::io::stdout();
    // Parallel iterators to process all since generate usernames until get hashes and compare
    StringsGenerator::new(options.max_length.into(), DICTIONARY)
    .par_bridge()
    .flat_map(|username| {
        options.domains.par_iter().map(move |domain| {
            format!("{}@{}", username, domain)
        })
    })
    .map(|email| {
        let mut hasher = Sha256::new();
        hasher.update(&email);
        let email_sha256_hex = hex::encode(hasher.finalize());
        (email, email_sha256_hex)
    })
    .filter(|(_email, email_sha256_hex)| {
        options.hashed_emails.par_iter().any(|looking_hash| {
            email_sha256_hex == looking_hash
        })
    })
    .for_each(|(email, email_sha256_hex)| {
        let mut handle = stdout.lock();
        if writeln!(handle, "{}{}{}", email, options.separator, email_sha256_hex).is_err() {
            panic!("Can NOT write result to stdout");
        }
    });
}
