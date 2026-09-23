// exec(req.query.command) should not trigger in a comment.
// const password = 'real-looking-but-commented';
const note = "Documentation says fetch(req.query.url), but this string is not executed.";
const harmless = "cors({ origin: '*' }) appears in a tutorial string.";
