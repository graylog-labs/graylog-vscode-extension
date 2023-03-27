"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.newFileSource = void 0;
function newFileSource(title) {
    return `rule "${title}"
    when
    // Set the conditions of your rule
    true
then
    // Develop the activities to take place within your rule
    // The Function documentation is here: 
    // https://go2docs.graylog.org/5-0/making_sense_of_your_log_data/functions_index.html

    // The Graylog Information Model (How to name your fields) is here:
    // https://schema.graylog.org

    // Thanks for using the Graylog VSCode Editor - Graylog Services Team
    
end`;
}
exports.newFileSource = newFileSource;
//# sourceMappingURL=constants.js.map