// //! A guest program to test that Device Detection lookups work properly.

// use fastly::device_detection::lookup;

fn main() {
    //     let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0 [FBAN/FBIOS;FBAV/8.0.0.28.18;FBBV/1665515;FBDV/iPhone4,1;FBMD/iPhone;FBSN/iPhone OS;FBSV/7.0.4;FBSS/2; FBCR/Telekom.de;FBID/phone;FBLC/de_DE;FBOP/5]";
    //     let device = lookup(&ua).unwrap();
    //     assert_eq!(device.device_name(), Some("iPhone"));
    //     assert_eq!(device.brand(), Some("Apple"));
    //     assert_eq!(device.model(), Some("iPhone4,1"));
    //     assert_eq!(device.hwtype(), Some("Mobile Phone"));
    //     assert_eq!(device.is_ereader(), Some(false));
    //     assert_eq!(device.is_gameconsole(), Some(false));
    //     assert_eq!(device.is_mediaplayer(), Some(false));
    //     assert_eq!(device.is_mobile(), Some(true));
    //     assert_eq!(device.is_smarttv(), Some(false));
    //     assert_eq!(device.is_tablet(), Some(false));
    //     assert_eq!(device.is_tvplayer(), Some(false));
    //     assert_eq!(device.is_desktop(), Some(false));
    //     assert_eq!(device.is_touchscreen(), Some(true));

    //     let ua = "ghosts-app/1.0.2.1 (ASUSTeK COMPUTER INC.; X550CC; Windows 8 (X86); en)";
    //     let device = lookup(&ua).unwrap();
    //     assert_eq!(device.device_name(), Some("Asus TeK"));
    //     assert_eq!(device.brand(), Some("Asus"));
    //     assert_eq!(device.model(), Some("TeK"));
    //     assert_eq!(device.hwtype(), None);
    //     assert_eq!(device.is_ereader(), None);
    //     assert_eq!(device.is_gameconsole(), None);
    //     assert_eq!(device.is_mediaplayer(), None);
    //     assert_eq!(device.is_mobile(), None);
    //     assert_eq!(device.is_smarttv(), None);
    //     assert_eq!(device.is_tablet(), None);
    //     assert_eq!(device.is_tvplayer(), None);
    //     assert_eq!(device.is_desktop(), Some(false));
    //     assert_eq!(device.is_touchscreen(), None);
}
