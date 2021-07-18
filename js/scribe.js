export function write_info(name, content) {
    localStorage.setItem(name, JSON
        .stringify([...Uint8Array
            .from(content)
            .values()]));
}

export function read_info(name) {
    return Uint8Array
        .from(JSON
            .parse(localStorage
            .getItem(name)));
}

export function check_exists(name) {
    return !!localStorage.getItem(name);
}