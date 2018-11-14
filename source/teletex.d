/**
    A module for converting text to and from Teletex (T.61).

	Authors:
        	$(LINK2 mailto:jonathan@wilbur.space, Jonathan M. Wilbur)
	Date: July 3rd, 2017
	Version: 1.0.0
	License: $(LINK2 https://mit-license.org, MIT License)
*/
module teletex;

/**
    From the T.61 Documentation:
    Diacritical marks, which are used in combination with the letters of the basic Latin alphabet in the primary
    set to constitute the coded representations of accented letters and umlauts. Each of these characters acts as a
    modifier indicating that the immediately following letter is to be transformed into an accented letter or an
    umlaut.

    ...

    Accented letters and umlauts: Each of these characters is represented by a sequence of two bit
    combinations. The first part of this sequence consists of a bit combination in the range 12/0 to 12/15
    (excluding 12/12) representing a diacritical mark. The second part consists of a bit combination in the
    range 4/1 to 5/10 or 6/1 to 7/10 representing a basic Latin letter.
*/

public
ubyte[] toTeletex(string value)
{
    ubyte[] ret;

    foreach (character; value)
    {
        switch (character)
        {
            case ('\x00'): ret ~= [ 0x00u ]; break;
            case ('\x01'): ret ~= [ 0x01u ]; break;
            case ('\x02'): ret ~= [ 0x02u ]; break;
            case ('\x03'): ret ~= [ 0x03u ]; break;
            case ('\x04'): ret ~= [ 0x04u ]; break;
            case ('\x05'): ret ~= [ 0x05u ]; break;
            case ('\x06'): ret ~= [ 0x06u ]; break;
            case ('\x07'): ret ~= [ 0x07u ]; break;
            case ('\x08'): ret ~= [ 0x08u ]; break;
            case ('\x09'): ret ~= [ 0x09u ]; break;
            case ('\x0A'): ret ~= [ 0x0Au ]; break;
            case ('\x0B'): ret ~= [ 0x0Bu ]; break;
            case ('\x0C'): ret ~= [ 0x0Cu ]; break;
            case ('\x0D'): ret ~= [ 0x0Du ]; break;
            case ('\x0E'): ret ~= [ 0x0Eu ]; break;
            case ('\x0F'): ret ~= [ 0x0Fu ]; break;
            case ('\x10'): ret ~= [ 0x10u ]; break;
            case ('\x11'): ret ~= [ 0x11u ]; break;
            case ('\x12'): ret ~= [ 0x12u ]; break;
            case ('\x13'): ret ~= [ 0x13u ]; break;
            case ('\x14'): ret ~= [ 0x14u ]; break;
            case ('\x15'): ret ~= [ 0x15u ]; break;
            case ('\x16'): ret ~= [ 0x16u ]; break;
            case ('\x17'): ret ~= [ 0x17u ]; break;
            case ('\x18'): ret ~= [ 0x18u ]; break;
            case ('\x19'): ret ~= [ 0x19u ]; break;
            case ('\x1A'): ret ~= [ 0x1Au ]; break;
            case ('\x1B'): ret ~= [ 0x1Bu ]; break;
            case ('\x1C'): ret ~= [ 0x1Cu ]; break;
            case ('\x1D'): ret ~= [ 0x1Du ]; break;
            case ('\x1E'): ret ~= [ 0x1Eu ]; break;
            case ('\x1F'): ret ~= [ 0x1Fu ]; break;
            case ('\x20'): ret ~= [ 0x20u ]; break;
            case ('\x21'): ret ~= [ 0x21u ]; break;
            case ('\x22'): ret ~= [ 0x22u ]; break;
            case ('\x23'): ret ~= [ 0xA6u ]; break;
            case ('\x24'): ret ~= [ 0xA4u ]; break;
            case ('\x25'): ret ~= [ 0x25u ]; break;
            case ('\x26'): ret ~= [ 0x26u ]; break;
            case ('\x27'): ret ~= [ 0x27u ]; break;
            case ('\x28'): ret ~= [ 0x28u ]; break;
            case ('\x29'): ret ~= [ 0x29u ]; break;
            case ('\x2A'): ret ~= [ 0x2Au ]; break;
            case ('\x2B'): ret ~= [ 0x2Bu ]; break;
            case ('\x2C'): ret ~= [ 0x2Cu ]; break;
            case ('\x2D'): ret ~= [ 0x2Du ]; break;
            case ('\x2E'): ret ~= [ 0x2Eu ]; break;
            case ('\x2F'): ret ~= [ 0x2Fu ]; break;
            case ('\x30'): ret ~= [ 0x30u ]; break;
            case ('\x31'): ret ~= [ 0x31u ]; break;
            case ('\x32'): ret ~= [ 0x32u ]; break;
            case ('\x33'): ret ~= [ 0x33u ]; break;
            case ('\x34'): ret ~= [ 0x34u ]; break;
            case ('\x35'): ret ~= [ 0x35u ]; break;
            case ('\x36'): ret ~= [ 0x36u ]; break;
            case ('\x37'): ret ~= [ 0x37u ]; break;
            case ('\x38'): ret ~= [ 0x38u ]; break;
            case ('\x39'): ret ~= [ 0x39u ]; break;
            case ('\x3A'): ret ~= [ 0x3Au ]; break;
            case ('\x3B'): ret ~= [ 0x3Bu ]; break;
            case ('\x3C'): ret ~= [ 0x3Cu ]; break;
            case ('\x3D'): ret ~= [ 0x3Du ]; break;
            case ('\x3E'): ret ~= [ 0x3Eu ]; break;
            case ('\x3F'): ret ~= [ 0x3Fu ]; break;
            case ('\x40'): ret ~= [ 0x40u ]; break;
            case ('\x41'): ret ~= [ 0x41u ]; break;
            case ('\x42'): ret ~= [ 0x42u ]; break;
            case ('\x43'): ret ~= [ 0x43u ]; break;
            case ('\x44'): ret ~= [ 0x44u ]; break;
            case ('\x45'): ret ~= [ 0x45u ]; break;
            case ('\x46'): ret ~= [ 0x46u ]; break;
            case ('\x47'): ret ~= [ 0x47u ]; break;
            case ('\x48'): ret ~= [ 0x48u ]; break;
            case ('\x49'): ret ~= [ 0x49u ]; break;
            case ('\x4A'): ret ~= [ 0x4Au ]; break;
            case ('\x4B'): ret ~= [ 0x4Bu ]; break;
            case ('\x4C'): ret ~= [ 0x4Cu ]; break;
            case ('\x4D'): ret ~= [ 0x4Du ]; break;
            case ('\x4E'): ret ~= [ 0x4Eu ]; break;
            case ('\x4F'): ret ~= [ 0x4Fu ]; break;
            case ('\x50'): ret ~= [ 0x50u ]; break;
            case ('\x51'): ret ~= [ 0x51u ]; break;
            case ('\x52'): ret ~= [ 0x52u ]; break;
            case ('\x53'): ret ~= [ 0x53u ]; break;
            case ('\x54'): ret ~= [ 0x54u ]; break;
            case ('\x55'): ret ~= [ 0x55u ]; break;
            case ('\x56'): ret ~= [ 0x56u ]; break;
            case ('\x57'): ret ~= [ 0x57u ]; break;
            case ('\x58'): ret ~= [ 0x58u ]; break;
            case ('\x59'): ret ~= [ 0x59u ]; break;
            case ('\x5A'): ret ~= [ 0x5Au ]; break;
            case ('\x5B'): ret ~= [ 0x5Bu ]; break;
            // case ('\x5C'): ret ~= [ 0x5Cu ]; break; There is no backslash in Teletex
            case ('\x5D'): ret ~= [ 0x5Du ]; break;
            // case ('\x5E'): ret ~= [ 0x5Eu ]; break; There is no caret in Teletex
            case ('\x5F'): ret ~= [ 0x5Fu ]; break;
            case ('\x60'): ret ~= [ 0xC1u ]; break; // 
            case ('\x61'): ret ~= [ 0x61u ]; break;
            case ('\x62'): ret ~= [ 0x62u ]; break;
            case ('\x63'): ret ~= [ 0x63u ]; break;
            case ('\x64'): ret ~= [ 0x64u ]; break;
            case ('\x65'): ret ~= [ 0x65u ]; break;
            case ('\x66'): ret ~= [ 0x66u ]; break;
            case ('\x67'): ret ~= [ 0x67u ]; break;
            case ('\x68'): ret ~= [ 0x68u ]; break;
            case ('\x69'): ret ~= [ 0x69u ]; break;
            case ('\x6A'): ret ~= [ 0x6Au ]; break;
            case ('\x6B'): ret ~= [ 0x6Bu ]; break;
            case ('\x6C'): ret ~= [ 0x6Cu ]; break;
            case ('\x6D'): ret ~= [ 0x6Du ]; break;
            case ('\x6E'): ret ~= [ 0x6Eu ]; break;
            case ('\x6F'): ret ~= [ 0x6Fu ]; break;
            case ('\x70'): ret ~= [ 0x70u ]; break;
            case ('\x71'): ret ~= [ 0x71u ]; break;
            case ('\x72'): ret ~= [ 0x72u ]; break;
            case ('\x73'): ret ~= [ 0x73u ]; break;
            case ('\x74'): ret ~= [ 0x74u ]; break;
            case ('\x75'): ret ~= [ 0x75u ]; break;
            case ('\x76'): ret ~= [ 0x76u ]; break;
            case ('\x77'): ret ~= [ 0x77u ]; break;
            case ('\x78'): ret ~= [ 0x78u ]; break;
            case ('\x79'): ret ~= [ 0x79u ]; break;
            case ('\x7A'): ret ~= [ 0x7Au ]; break;
            // case ('\x7B'): ret ~= [ 0x7Bu ]; break; There is no opening curly bracket in Teletex
            case ('\x7C'): ret ~= [ 0x7Cu ]; break;
            // case ('\x7D'): ret ~= [ 0x7Du ]; break; There is not closing curly bracket in Teletex
            // case ('\x7E'): ret ~= [ 0x7Eu ]; break; There is no tilda in Teletex
            case ('\x7F'): ret ~= [ 0x7Fu ]; break;
            case ('\x80'): ret ~= [ 0x80u ]; break;
            case ('\x81'): ret ~= [ 0x81u ]; break;
            case ('\x82'): ret ~= [ 0x82u ]; break;
            case ('\x83'): ret ~= [ 0x83u ]; break;
            case ('\x84'): ret ~= [ 0x84u ]; break;
            case ('\x85'): ret ~= [ 0x85u ]; break;
            case ('\x86'): ret ~= [ 0x86u ]; break;
            case ('\x87'): ret ~= [ 0x87u ]; break;
            case ('\x88'): ret ~= [ 0x88u ]; break;
            case ('\x89'): ret ~= [ 0x89u ]; break;
            case ('\x8A'): ret ~= [ 0x8Au ]; break;
            case ('\x8B'): ret ~= [ 0x8Bu ]; break;
            case ('\x8C'): ret ~= [ 0x8Cu ]; break;
            case ('\x8D'): ret ~= [ 0x8Du ]; break;
            case ('\x8E'): ret ~= [ 0x8Eu ]; break;
            case ('\x8F'): ret ~= [ 0x8Fu ]; break;
            case ('\x90'): ret ~= [ 0x90u ]; break;
            case ('\x91'): ret ~= [ 0x91u ]; break;
            case ('\x92'): ret ~= [ 0x92u ]; break;
            case ('\x93'): ret ~= [ 0x93u ]; break;
            case ('\x94'): ret ~= [ 0x94u ]; break;
            case ('\x95'): ret ~= [ 0x95u ]; break;
            case ('\x96'): ret ~= [ 0x96u ]; break;
            case ('\x97'): ret ~= [ 0x97u ]; break;
            case ('\x98'): ret ~= [ 0x98u ]; break;
            case ('\x99'): ret ~= [ 0x99u ]; break;
            case ('\x9A'): ret ~= [ 0x9Au ]; break;
            case ('\x9B'): ret ~= [ 0x9Bu ]; break;
            case ('\x9C'): ret ~= [ 0x9Cu ]; break;
            case ('\x9D'): ret ~= [ 0x9Du ]; break;
            case ('\x9E'): ret ~= [ 0x9Eu ]; break;
            case ('\x9F'): ret ~= [ 0x9Fu ]; break;
            case ('\xA0'): ret ~= [ 0xA0u ]; break;
            case ('\xA1'): ret ~= [ 0xA1u ]; break;
            case ('\xA2'): ret ~= [ 0xA2u ]; break;
            case ('\xA3'): ret ~= [ 0xA3u ]; break;
            case ('\xA4'): ret ~= [ 0xA8u ]; break; //
            case ('\xA5'): ret ~= [ 0xA5u ]; break;
            // case ('\xA6'): ret ~= [ 0xA6u ]; break; There is no Broken Bar in Teletex
            case ('\xA7'): ret ~= [ 0xA7u ]; break;
            case ('\xA8'): ret ~= [ 0xC8u ]; break; //
            // case ('\xA9'): ret ~= [ 0xA9u ]; break; There is no Copyright in Teletex
            // case ('\xAA'): ret ~= [ 0xAAu ]; break; There is no Feminine Ordinal Indicator in Teletex
            case ('\xAB'): ret ~= [ 0xABu ]; break;
            // case ('\xAC'): ret ~= [ 0xACu ]; break; There is no Not Sign in Teletex
            // case ('\xAD'): ret ~= [ 0xADu ]; break; REVIEW: I do not think there is a Soft Hyphen in Teletex
            // case ('\xAE'): ret ~= [ 0xAEu ]; break; There is no Registered in Teletex
            case ('\xAF'): ret ~= [ 0xC5u ]; break; //
            // case ('\xB0'): ret ~= [ 0xB0u ]; break; There is no Degree in Teletex
            case ('\xB1'): ret ~= [ 0xB1u ]; break;
            case ('\xB2'): ret ~= [ 0xB2u ]; break;
            case ('\xB3'): ret ~= [ 0xB3u ]; break;
            case ('\xB4'): ret ~= [ 0xC2u ]; break; // REVIEW
            case ('\xB5'): ret ~= [ 0xB5u ]; break;
            case ('\xB6'): ret ~= [ 0xB6u ]; break;
            case ('\xB7'): ret ~= [ 0xB7u ]; break;
            // case ('\xB8'): ret ~= [ 0xB8u ]; break; There is no Cedilla in Teletex
            // case ('\xB9'): ret ~= [ 0xB9u ]; break; There is no Superscript One in Teletex
            // case ('\xBA'): ret ~= [ 0xBAu ]; break; There is no Masculine Ordinal Indicator in Teletex
            case ('\xBB'): ret ~= [ 0xBBu ]; break;
            case ('\xBC'): ret ~= [ 0xBCu ]; break;
            case ('\xBD'): ret ~= [ 0xBDu ]; break;
            case ('\xBE'): ret ~= [ 0xBEu ]; break;
            case ('\xBF'): ret ~= [ 0xBFu ]; break;
            case ('\xC0'): ret ~= [ 0xC1u, 0x41u ]; break; //
            case ('\xC1'): ret ~= [ 0xC2u, 0x41u ]; break; //
            case ('\xC2'): ret ~= [ 0xC3u, 0x41u ]; break;
            case ('\xC3'): ret ~= [ 0xC4u, 0x41u ]; break;
            case ('\xC4'): ret ~= [ 0xC5u, 0x41u ]; break;
            case ('\xC5'): ret ~= [ 0xCAu, 0x41u ]; break;
            case ('\xC6'): ret ~= [ 0xE1u ]; break;
            // case ('\xC7'): ret ~= [ 0xC7u ]; break; There is no C with Cedilla in Teletex
            case ('\xC8'): ret ~= [ 0xC1u, 0x45u ]; break; //
            case ('\xC9'): ret ~= [ 0xC2u, 0x45u ]; break; //
            case ('\xCA'): ret ~= [ 0xC3u, 0x45u ]; break; //
            case ('\xCB'): ret ~= [ 0xC8u, 0x45u ]; break; //
            case ('\xCC'): ret ~= [ 0xC1u, 0x49u ]; break; //
            case ('\xCD'): ret ~= [ 0xC2u, 0x49u ]; break; //
            case ('\xCE'): ret ~= [ 0xC3u, 0x49u ]; break; //
            case ('\xCF'): ret ~= [ 0xC8u, 0x49u ]; break; //
            case ('\xD0'): ret ~= [ 0xE2u ]; break; //
            case ('\xD1'): ret ~= [ 0xC4u, 0x4Eu ]; break; //
            case ('\xD2'): ret ~= [ 0xC1u, 0x4Fu ]; break; //
            case ('\xD3'): ret ~= [ 0xC2u, 0x4Fu ]; break; //
            case ('\xD4'): ret ~= [ 0xC3u, 0x4Fu ]; break; //
            case ('\xD5'): ret ~= [ 0xC4u, 0x4Fu ]; break; //
            case ('\xD6'): ret ~= [ 0xC8u, 0x4Fu ]; break; //
            case ('\xD7'): ret ~= [ 0xB4u ]; break; // REVIEW
            case ('\xD8'): ret ~= [ 0xE9u ]; break; //
            case ('\xD9'): ret ~= [ 0xC1u, 0x55u ]; break; //
            case ('\xDA'): ret ~= [ 0xC2u, 0x55u ]; break; //
            case ('\xDB'): ret ~= [ 0xC3u, 0x55u ]; break; //
            case ('\xDC'): ret ~= [ 0xC8u, 0x55u ]; break; //
            case ('\xDD'): ret ~= [ 0xC2u, 0x59u ]; break; //
            case ('\xDE'): ret ~= [ 0xECu ]; break; //
            case ('\xDF'): ret ~= [ 0xFCu ]; break; // REVIEW
            case ('\xE0'): ret ~= [ 0xC1u, 0x61u ]; break;
            case ('\xE1'): ret ~= [ 0xC2u, 0x61u ]; break;
            case ('\xE2'): ret ~= [ 0xC3u, 0x61u ]; break;
            case ('\xE3'): ret ~= [ 0xC4u, 0x61u ]; break;
            case ('\xE4'): ret ~= [ 0xC8u, 0x61u ]; break;
            case ('\xE5'): ret ~= [ 0xCAu, 0x61u ]; break;
            case ('\xE6'): ret ~= [ 0xF1u ]; break;
            // case ('\xE7'): ret ~= [ 0xE7u ]; break; There is no Small C with Cedilla in Teletex
            case ('\xE8'): ret ~= [ 0xC1u, 0x65u ]; break;
            case ('\xE9'): ret ~= [ 0xC2u, 0x65u ]; break;
            case ('\xEA'): ret ~= [ 0xC3u, 0x65u ]; break;
            case ('\xEB'): ret ~= [ 0xC8u, 0x65u ]; break;
            case ('\xEC'): ret ~= [ 0xC1u, 0x69u ]; break;
            case ('\xED'): ret ~= [ 0xC2u, 0x69u ]; break;
            case ('\xEE'): ret ~= [ 0xC3u, 0x69u ]; break;
            case ('\xEF'): ret ~= [ 0xC8u, 0x69u ]; break;
            case ('\xF0'): ret ~= [ 0xF3u ]; break;
            case ('\xF1'): ret ~= [ 0xC4u, 0x6Eu ]; break;
            case ('\xF2'): ret ~= [ 0xC1u, 0x6Fu ]; break;
            case ('\xF3'): ret ~= [ 0xC2u, 0x6Fu ]; break;
            case ('\xF4'): ret ~= [ 0xC3u, 0x6Fu ]; break;
            case ('\xF5'): ret ~= [ 0xC4u, 0x6Fu ]; break;
            case ('\xF6'): ret ~= [ 0xC8u, 0x6Fu ]; break;
            case ('\xF7'): ret ~= [ 0xB8u ]; break; //
            case ('\xF8'): ret ~= [ 0xF9u ]; break; //
            case ('\xF9'): ret ~= [ 0xC1u, 0x75u ]; break;
            case ('\xFA'): ret ~= [ 0xC2u, 0x75u ]; break;
            case ('\xFB'): ret ~= [ 0xC3u, 0x75u ]; break;
            case ('\xFC'): ret ~= [ 0xC8u, 0x75u ]; break;
            case ('\xFD'): ret ~= [ 0xC2u, 0x79u ]; break;
            case ('\xFE'): ret ~= [ 0xFCu ]; break;
            case ('\xFF'): ret ~= [ 0xC8u, 0x79u ]; break;
            default:
                throw new Exception("DUN GOOFED");
                break;
        }
    }

    return ret;
}

public
string fromTeletex(ubyte[] value ...)
{
    string ret;

    foreach (character; value)
    {
        switch (character)
        {
            case (0x00u): ret ~= [ '\x00' ]; break;
            case (0x01u): ret ~= [ '\x01' ]; break;
            case (0x02u): ret ~= [ '\x02' ]; break;
            case (0x03u): ret ~= [ '\x03' ]; break;
            case (0x04u): ret ~= [ '\x04' ]; break;
            case (0x05u): ret ~= [ '\x05' ]; break;
            case (0x06u): ret ~= [ '\x06' ]; break;
            case (0x07u): ret ~= [ '\x07' ]; break;
            case (0x08u): ret ~= [ '\x08' ]; break;
            case (0x09u): ret ~= [ '\x09' ]; break;
            case (0x0Au): ret ~= [ '\x0A' ]; break;
            case (0x0Bu): ret ~= [ '\x0B' ]; break;
            case (0x0Cu): ret ~= [ '\x0C' ]; break;
            case (0x0Du): ret ~= [ '\x0D' ]; break;
            case (0x0Eu): ret ~= [ '\x0E' ]; break;
            case (0x0Fu): ret ~= [ '\x0F' ]; break;
            case (0x10u): ret ~= [ '\x10' ]; break;
            case (0x11u): ret ~= [ '\x11' ]; break;
            case (0x12u): ret ~= [ '\x12' ]; break;
            case (0x13u): ret ~= [ '\x13' ]; break;
            case (0x14u): ret ~= [ '\x14' ]; break;
            case (0x15u): ret ~= [ '\x15' ]; break;
            case (0x16u): ret ~= [ '\x16' ]; break;
            case (0x17u): ret ~= [ '\x17' ]; break;
            case (0x18u): ret ~= [ '\x18' ]; break;
            case (0x19u): ret ~= [ '\x19' ]; break;
            case (0x1Au): ret ~= [ '\x1A' ]; break;
            case (0x1Bu): ret ~= [ '\x1B' ]; break;
            case (0x1Cu): ret ~= [ '\x1C' ]; break;
            case (0x1Du): ret ~= [ '\x1D' ]; break;
            case (0x1Eu): ret ~= [ '\x1E' ]; break;
            case (0x1Fu): ret ~= [ '\x1F' ]; break;
            case (0x20u): ret ~= [ '\x20' ]; break;
            case (0x21u): ret ~= [ '\x21' ]; break;
            case (0x22u): ret ~= [ '\x22' ]; break;
            case (0x23u): ret ~= [ '\x23' ]; break;
            case (0x24u): ret ~= [ '\xA4' ]; break; //
            case (0x25u): ret ~= [ '\x25' ]; break;
            case (0x26u): ret ~= [ '\x26' ]; break;
            case (0x27u): ret ~= [ '\x27' ]; break;
            case (0x28u): ret ~= [ '\x28' ]; break;
            case (0x29u): ret ~= [ '\x29' ]; break;
            case (0x2Au): ret ~= [ '\x2A' ]; break;
            case (0x2Bu): ret ~= [ '\x2B' ]; break;
            case (0x2Cu): ret ~= [ '\x2C' ]; break;
            case (0x2Du): ret ~= [ '\x2D' ]; break;
            case (0x2Eu): ret ~= [ '\x2E' ]; break;
            case (0x2Fu): ret ~= [ '\x2F' ]; break;
            case (0x30u): ret ~= [ '\x30' ]; break;
            case (0x31u): ret ~= [ '\x31' ]; break;
            case (0x32u): ret ~= [ '\x32' ]; break;
            case (0x33u): ret ~= [ '\x33' ]; break;
            case (0x34u): ret ~= [ '\x34' ]; break;
            case (0x35u): ret ~= [ '\x35' ]; break;
            case (0x36u): ret ~= [ '\x36' ]; break;
            case (0x37u): ret ~= [ '\x37' ]; break;
            case (0x38u): ret ~= [ '\x38' ]; break;
            case (0x39u): ret ~= [ '\x39' ]; break;
            case (0x3Au): ret ~= [ '\x3A' ]; break;
            case (0x3Bu): ret ~= [ '\x3B' ]; break;
            case (0x3Cu): ret ~= [ '\x3C' ]; break;
            case (0x3Du): ret ~= [ '\x3D' ]; break;
            case (0x3Eu): ret ~= [ '\x3E' ]; break;
            case (0x3Fu): ret ~= [ '\x3F' ]; break;
            case (0x40u): ret ~= [ '\x40' ]; break;
            case (0x41u): ret ~= [ '\x41' ]; break;
            case (0x42u): ret ~= [ '\x42' ]; break;
            case (0x43u): ret ~= [ '\x43' ]; break;
            case (0x44u): ret ~= [ '\x44' ]; break;
            case (0x45u): ret ~= [ '\x45' ]; break;
            case (0x46u): ret ~= [ '\x46' ]; break;
            case (0x47u): ret ~= [ '\x47' ]; break;
            case (0x48u): ret ~= [ '\x48' ]; break;
            case (0x49u): ret ~= [ '\x49' ]; break;
            case (0x4Au): ret ~= [ '\x4A' ]; break;
            case (0x4Bu): ret ~= [ '\x4B' ]; break;
            case (0x4Cu): ret ~= [ '\x4C' ]; break;
            case (0x4Du): ret ~= [ '\x4D' ]; break;
            case (0x4Eu): ret ~= [ '\x4E' ]; break;
            case (0x4Fu): ret ~= [ '\x4F' ]; break;
            case (0x50u): ret ~= [ '\x50' ]; break;
            case (0x51u): ret ~= [ '\x51' ]; break;
            case (0x52u): ret ~= [ '\x52' ]; break;
            case (0x53u): ret ~= [ '\x53' ]; break;
            case (0x54u): ret ~= [ '\x54' ]; break;
            case (0x55u): ret ~= [ '\x55' ]; break;
            case (0x56u): ret ~= [ '\x56' ]; break;
            case (0x57u): ret ~= [ '\x57' ]; break;
            case (0x58u): ret ~= [ '\x58' ]; break;
            case (0x59u): ret ~= [ '\x59' ]; break;
            case (0x5Au): ret ~= [ '\x5A' ]; break;
            case (0x5Bu): ret ~= [ '\x5B' ]; break;
            // case (0x5Cu): ret ~= [ '\x5C' ]; break; //
            case (0x5Du): ret ~= [ '\x5D' ]; break;
            // case (0x5Eu): ret ~= [ '\x5E' ]; break;
            case (0x5Fu): ret ~= [ '\x5F' ]; break;
            // case (0x60u): ret ~= [ '\x60' ]; break;
            case (0x61u): ret ~= [ '\x61' ]; break;
            case (0x62u): ret ~= [ '\x62' ]; break;
            case (0x63u): ret ~= [ '\x63' ]; break;
            case (0x64u): ret ~= [ '\x64' ]; break;
            case (0x65u): ret ~= [ '\x65' ]; break;
            case (0x66u): ret ~= [ '\x66' ]; break;
            case (0x67u): ret ~= [ '\x67' ]; break;
            case (0x68u): ret ~= [ '\x68' ]; break;
            case (0x69u): ret ~= [ '\x69' ]; break;
            case (0x6Au): ret ~= [ '\x6A' ]; break;
            case (0x6Bu): ret ~= [ '\x6B' ]; break;
            case (0x6Cu): ret ~= [ '\x6C' ]; break;
            case (0x6Du): ret ~= [ '\x6D' ]; break;
            case (0x6Eu): ret ~= [ '\x6E' ]; break;
            case (0x6Fu): ret ~= [ '\x6F' ]; break;
            case (0x70u): ret ~= [ '\x70' ]; break;
            case (0x71u): ret ~= [ '\x71' ]; break;
            case (0x72u): ret ~= [ '\x72' ]; break;
            case (0x73u): ret ~= [ '\x73' ]; break;
            case (0x74u): ret ~= [ '\x74' ]; break;
            case (0x75u): ret ~= [ '\x75' ]; break;
            case (0x76u): ret ~= [ '\x76' ]; break;
            case (0x77u): ret ~= [ '\x77' ]; break;
            case (0x78u): ret ~= [ '\x78' ]; break;
            case (0x79u): ret ~= [ '\x79' ]; break;
            case (0x7Au): ret ~= [ '\x7A' ]; break;
            // case (0x7Bu): ret ~= [ '\x7B' ]; break;
            case (0x7Cu): ret ~= [ '\x7C' ]; break;
            // case (0x7Du): ret ~= [ '\x7D' ]; break;
            // case (0x7Eu): ret ~= [ '\x7E' ]; break;
            case (0x7Fu): ret ~= [ '\x7F' ]; break;
            case (0x80u): ret ~= [ '\x80' ]; break;
            case (0x81u): ret ~= [ '\x81' ]; break;
            case (0x82u): ret ~= [ '\x82' ]; break;
            case (0x83u): ret ~= [ '\x83' ]; break;
            case (0x84u): ret ~= [ '\x84' ]; break;
            case (0x85u): ret ~= [ '\x85' ]; break;
            case (0x86u): ret ~= [ '\x86' ]; break;
            case (0x87u): ret ~= [ '\x87' ]; break;
            case (0x88u): ret ~= [ '\x88' ]; break;
            case (0x89u): ret ~= [ '\x89' ]; break;
            case (0x8Au): ret ~= [ '\x8A' ]; break;
            case (0x8Bu): ret ~= [ '\x8B' ]; break;
            case (0x8Cu): ret ~= [ '\x8C' ]; break;
            case (0x8Du): ret ~= [ '\x8D' ]; break;
            case (0x8Eu): ret ~= [ '\x8E' ]; break;
            case (0x8Fu): ret ~= [ '\x8F' ]; break;
            case (0x90u): ret ~= [ '\x90' ]; break;
            case (0x91u): ret ~= [ '\x91' ]; break;
            case (0x92u): ret ~= [ '\x92' ]; break;
            case (0x93u): ret ~= [ '\x93' ]; break;
            case (0x94u): ret ~= [ '\x94' ]; break;
            case (0x95u): ret ~= [ '\x95' ]; break;
            case (0x96u): ret ~= [ '\x96' ]; break;
            case (0x97u): ret ~= [ '\x97' ]; break;
            case (0x98u): ret ~= [ '\x98' ]; break;
            case (0x99u): ret ~= [ '\x99' ]; break;
            case (0x9Au): ret ~= [ '\x9A' ]; break;
            case (0x9Bu): ret ~= [ '\x9B' ]; break;
            case (0x9Cu): ret ~= [ '\x9C' ]; break;
            case (0x9Du): ret ~= [ '\x9D' ]; break;
            case (0x9Eu): ret ~= [ '\x9E' ]; break;
            case (0x9Fu): ret ~= [ '\x9F' ]; break;
            case (0xA0u): ret ~= [ '\xA0' ]; break;
            case (0xA1u): ret ~= [ '\xA1' ]; break;
            case (0xA2u): ret ~= [ '\xA2' ]; break;
            case (0xA3u): ret ~= [ '\xA3' ]; break;
            case (0xA4u): ret ~= [ '\x24' ]; break;
            case (0xA5u): ret ~= [ '\xA5' ]; break;
            case (0xA6u): ret ~= [ '\x23' ]; break; //
            case (0xA7u): ret ~= [ '\xA7' ]; break;
            case (0xA8u): ret ~= [ '\xA4' ]; break; //
            // case (0xA9u): ret ~= [ '\xA9' ]; break;
            // case (0xAAu): ret ~= [ '\xAA' ]; break;
            case (0xABu): ret ~= [ '\xAB' ]; break;
            // case (0xACu): ret ~= [ '\xAC' ]; break;
            // case (0xADu): ret ~= [ '\xAD' ]; break;
            // case (0xAEu): ret ~= [ '\xAE' ]; break;
            // case (0xAFu): ret ~= [ '\xAF' ]; break;
            case (0xB0u): ret ~= [ '\xB0' ]; break;
            case (0xB1u): ret ~= [ '\xB1' ]; break;
            case (0xB2u): ret ~= [ '\xB2' ]; break;
            case (0xB3u): ret ~= [ '\xB3' ]; break;
            case (0xB4u): ret ~= [ '\xD7' ]; break; // REVIEW
            case (0xB5u): ret ~= [ '\xB5' ]; break;
            case (0xB6u): ret ~= [ '\xB6' ]; break;
            case (0xB7u): ret ~= [ '\xB7' ]; break;
            case (0xB8u): ret ~= [ '\xF7' ]; break; //
            // case (0xB9u): ret ~= [ '\xB9' ]; break;
            // case (0xBAu): ret ~= [ '\xBA' ]; break;
            case (0xBBu): ret ~= [ '\xBB' ]; break;
            case (0xBCu): ret ~= [ '\xBC' ]; break;
            case (0xBDu): ret ~= [ '\xBD' ]; break;
            case (0xBEu): ret ~= [ '\xBE' ]; break;
            case (0xBFu): ret ~= [ '\xBF' ]; break;
            // case (0xC0u): ret ~= [ '\xC0' ]; break;
            case (0xC1u): ret ~= [ '\xC1' ]; break;
            case (0xC2u): ret ~= [ '\xC2' ]; break;
            case (0xC3u): ret ~= [ '\xC3' ]; break;
            case (0xC4u): ret ~= [ '\xC4' ]; break;
            case (0xC5u): ret ~= [ '\xC5' ]; break;
            case (0xC6u): ret ~= [ '\xC6' ]; break;
            case (0xC7u): ret ~= [ '\xC7' ]; break;
            case (0xC8u): ret ~= [ '\xC8' ]; break;
            case (0xC9u): ret ~= [ '\xC9' ]; break;
            case (0xCAu): ret ~= [ '\xCA' ]; break;
            case (0xCBu): ret ~= [ '\xCB' ]; break;
            case (0xCCu): ret ~= [ '\xCC' ]; break;
            case (0xCDu): ret ~= [ '\xCD' ]; break;
            case (0xCEu): ret ~= [ '\xCE' ]; break;
            case (0xCFu): ret ~= [ '\xCF' ]; break;
            // case (0xD0u): ret ~= [ '\xD0' ]; break;
            // case (0xD1u): ret ~= [ '\xD1' ]; break;
            // case (0xD2u): ret ~= [ '\xD2' ]; break;
            // case (0xD3u): ret ~= [ '\xD3' ]; break;
            // case (0xD4u): ret ~= [ '\xD4' ]; break;
            // case (0xD5u): ret ~= [ '\xD5' ]; break;
            // case (0xD6u): ret ~= [ '\xD6' ]; break;
            // case (0xD7u): ret ~= [ '\xD7' ]; break;
            // case (0xD8u): ret ~= [ '\xD8' ]; break;
            // case (0xD9u): ret ~= [ '\xD9' ]; break;
            // case (0xDAu): ret ~= [ '\xDA' ]; break;
            // case (0xDBu): ret ~= [ '\xDB' ]; break;
            // case (0xDCu): ret ~= [ '\xDC' ]; break;
            // case (0xDDu): ret ~= [ '\xDD' ]; break;
            // case (0xDEu): ret ~= [ '\xDE' ]; break;
            // case (0xDFu): ret ~= [ '\xDF' ]; break;
            case (0xE0u): ret ~= [ '\u03A9' ]; break; // REVIEW
            case (0xE1u): ret ~= [ '\xC6' ]; break;
            case (0xE2u): ret ~= [ '\u0110' ]; break;
            case (0xE3u): ret ~= [ '\xAA' ]; break;
            case (0xE4u): ret ~= [ '\u0126' ]; break;
            // case (0xE5u): ret ~= [ '\xE5' ]; break;
            case (0xE6u): ret ~= [ '\u0132' ]; break;
            case (0xE7u): ret ~= [ '\u013F' ]; break;
            case (0xE8u): ret ~= [ '\u0141' ]; break;
            case (0xE9u): ret ~= [ '\xD8' ]; break;
            case (0xEAu): ret ~= [ '\u0152' ]; break;
            case (0xEBu): ret ~= [ '\xBA' ]; break;
            case (0xECu): ret ~= [ '\xDE' ]; break;
            case (0xEDu): ret ~= [ '\u0166' ]; break;
            case (0xEEu): ret ~= [ '\u014A' ]; break;
            case (0xEFu): ret ~= [ '\u0149' ]; break;
            case (0xF0u): ret ~= [ '\u039A' ]; break; // REVIEW
            case (0xF1u): ret ~= [ '\xE6' ]; break;
            case (0xF2u): ret ~= [ '\u0111' ]; break;
            case (0xF3u): ret ~= [ '\xF0' ]; break;
            case (0xF4u): ret ~= [ '\u0127' ]; break;
            case (0xF5u): ret ~= [ '\xF5' ]; break; // REVIEW: I don't know what that symbol is.
            case (0xF6u): ret ~= [ '\u0133' ]; break;
            case (0xF7u): ret ~= [ '\u0140' ]; break;
            case (0xF8u): ret ~= [ '\u0142' ]; break;
            case (0xF9u): ret ~= [ '\xF8' ]; break;
            case (0xFAu): ret ~= [ '\u0153' ]; break;
            case (0xFBu): ret ~= [ '\xDF' ]; break; // REVIEW: Just make sure that is a strong S instead of a beta.
            case (0xFCu): ret ~= [ '\xFE' ]; break;
            case (0xFDu): ret ~= [ '\u0167' ]; break;
            case (0xFEu): ret ~= [ '\u014B' ]; break;
            // case (0xFFu): ret ~= [ '\xFF' ]; break;
            default:
                throw new Exception("DUN GOOFED");
                break;
        }
    }

    return ret;
}

