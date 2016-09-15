package edu.cmu.iccb;

import java.io.IOException;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import edu.cmu.iccb.services.ImageService;

@Controller
public class ImageController {

    
    private ImageService imageService;
    
    @Autowired
	public void setImageService(ImageService imageService) {
		this.imageService = imageService;
	}

    public ImageService getImageService() {
		return imageService;
	}


	@RequestMapping("/uploaded/image/{id}")
    public ResponseEntity<byte[]> getFullImage(@PathVariable String id) throws IOException {

        byte[] image = imageService.getImageData(id);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);
        
        return new ResponseEntity<byte[]>(image, headers, HttpStatus.OK);
    }
    
	@RequestMapping("/uploaded/thumbnail/{id}")
    public ResponseEntity<byte[]> getThumbnail(@PathVariable String id) throws IOException {

        byte[] image = imageService.getThumbnailData(id);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);
        
        return new ResponseEntity<byte[]>(image, headers, HttpStatus.OK);
    }


}
