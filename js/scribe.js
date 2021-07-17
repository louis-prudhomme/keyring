import { Pair } from "./../../../keyring";

export function write_info(name, content) {
    localStorage.setItem(name, content)
}

export function read_info(name) {
    return localStorage.getItem(name);
}